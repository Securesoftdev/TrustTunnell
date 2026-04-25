use crate::http_codec::{RequestHeaders, ResponseHeaders};
use crate::pipe::Sink;
use crate::settings::Settings;
use crate::tls_demultiplexer::Protocol;
use crate::{datagram_pipe, http_codec, log_id, log_utils, net_utils, pipe, utils};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

pub(crate) const MAX_RAW_HEADERS_SIZE: usize = 1024;
pub(crate) const MAX_HEADERS_NUM: usize = 32;

pub(crate) struct Http1Codec<IO> {
    state: State,
    transport_stream: IO,
    client_address: IpAddr,
    /// Receives messages from [`StreamSink.download_tx`]
    download_rx: mpsc::Receiver<Bytes>,
    /// See [`StreamSink.download_tx`]
    download_tx: Option<mpsc::Sender<Bytes>>,
    /// Waits notify from [`StreamSink.download_eof`]
    download_eof: Arc<Notify>,
    /// See [`StreamSource.upload_rx`]
    upload_rx: Option<mpsc::Receiver<Bytes>>,
    /// Sends messages to [`StreamSource.upload_rx`]
    upload_tx: mpsc::Sender<Bytes>,
    upload_buffer_size: usize,
    parent_id_chain: log_utils::IdChain<u64>,
    next_request_id: std::ops::RangeFrom<u64>,
}

pub(crate) enum DecodeStatus<Headers> {
    Partial(BytesMut),
    Complete(Headers, BytesMut),
}

enum State {
    WaitingRequest(WaitingRequest),
    RequestInProgress(RequestInProgress),
}

struct WaitingRequest {
    buffer: BytesMut,
}

struct RequestInProgress {
    buffer: BytesMut,
}

struct Stream {
    source: StreamSource,
    sink: StreamSink,
}

struct StreamSource {
    request: RequestHeaders,
    client_address: IpAddr,
    /// Receives messages from [`Http1Codec.upload_tx`]
    upload_rx: mpsc::Receiver<Bytes>,
    id: log_utils::IdChain<u64>,
}

struct StreamSink {
    /// Sends messages to [`Http1Codec.download_rx`]
    download_tx: Option<mpsc::Sender<Bytes>>,
    /// Notifies [`Http1Codec.download_eof`]
    download_eof: Arc<Notify>,
    insert_connection_close: bool,
    id: log_utils::IdChain<u64>,
}

enum RequestStatus {
    Partial,
    Complete(Box<dyn http_codec::Stream>),
    NeedRespond(ResponseHeaders),
}

impl<IO> Http1Codec<IO>
where
    IO: net_utils::PeerAddr,
{
    pub fn new(
        core_settings: Arc<Settings>,
        transport_stream: IO,
        client_address: IpAddr,
        parent_id_chain: log_utils::IdChain<u64>,
    ) -> Self {
        let (download_tx, download_rx) = mpsc::channel(1);
        let (upload_tx, upload_rx) = mpsc::channel(1);

        Self {
            state: State::WaitingRequest(WaitingRequest {
                buffer: BytesMut::with_capacity(MAX_RAW_HEADERS_SIZE),
            }),
            transport_stream,
            client_address,
            download_rx,
            download_tx: Some(download_tx),
            download_eof: Arc::new(Notify::new()),
            upload_rx: Some(upload_rx),
            upload_tx,
            upload_buffer_size: core_settings
                .listen_protocols
                .http1
                .as_ref()
                .unwrap()
                .upload_buffer_size,
            parent_id_chain,
            next_request_id: 0..,
        }
    }

    fn on_request_headers_chunk(&mut self, buffer: BytesMut) -> io::Result<RequestStatus> {
        match decode_request(buffer, MAX_HEADERS_NUM, MAX_RAW_HEADERS_SIZE)? {
            DecodeStatus::Partial(bytes) => {
                match &mut self.state {
                    State::WaitingRequest(x) => x.buffer = bytes,
                    _ => unreachable!(),
                }
                Ok(RequestStatus::Partial)
            }
            DecodeStatus::Complete(request, tail) => {
                if request.method == http::Method::CONNECT && request.headers.contains_key("expect")
                {
                    return Ok(RequestStatus::NeedRespond(
                        http::response::Builder::new()
                            .version(request.version)
                            .status(http::StatusCode::EXPECTATION_FAILED)
                            .header("Connection", "close")
                            .body(())
                            .map_err(|e| {
                                io::Error::new(
                                    ErrorKind::Other,
                                    format!(
                                        "Failed to build \"Expectation Failed\" response: {}",
                                        e
                                    ),
                                )
                            })?
                            .into_parts()
                            .0,
                    ));
                }

                let _ = std::mem::replace(
                    &mut self.state,
                    State::RequestInProgress(RequestInProgress { buffer: tail }),
                );

                let id = self.parent_id_chain.extended(log_utils::IdItem::new(
                    log_utils::CONNECTION_ID_FMT,
                    self.next_request_id.next().unwrap(),
                ));
                let insert_connection_close = request.method == http::Method::CONNECT;
                Ok(RequestStatus::Complete(Box::new(Stream {
                    source: StreamSource {
                        request,
                        client_address: self.client_address,
                        upload_rx: self.upload_rx.take().unwrap(),
                        id: id.clone(),
                    },
                    sink: StreamSink {
                        download_tx: self.download_tx.take(),
                        download_eof: self.download_eof.clone(),
                        insert_connection_close,
                        id,
                    },
                })))
            }
        }
    }
}

#[async_trait]
impl<IO> http_codec::HttpCodec for Http1Codec<IO>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + net_utils::PeerAddr,
{
    async fn listen(&mut self) -> io::Result<Option<Box<dyn http_codec::Stream>>> {
        loop {
            let wait_read = async {
                let mut buffer = self.state.take_buffer();
                if buffer.is_empty() {
                    if matches!(self.state, State::RequestInProgress(_)) {
                        let _ = self.upload_tx.reserve().await;
                    }
                    self.transport_stream.read_buf(&mut buffer).await?;
                } else if matches!(self.state, State::WaitingRequest(_)) {
                    let bytes_read = self.transport_stream.read_buf(&mut buffer).await?;
                    if bytes_read == 0 {
                        buffer.clear();
                    }
                }
                Ok(buffer)
            };

            tokio::select! {
                r = wait_read => match r {
                    Ok(bytes) if bytes.is_empty() =>
                        return self.graceful_shutdown().await.map(|()| None),
                    Ok(bytes) => match &mut self.state {
                        State::WaitingRequest(_) => {
                            match self.on_request_headers_chunk(bytes)? {
                                RequestStatus::Partial => (),
                                RequestStatus::Complete(stream) => return Ok(Some(stream)),
                                RequestStatus::NeedRespond(response) => {
                                    log_id!(debug, self.parent_id_chain, "Tunnel rejected, responding with: {:?}", response);
                                    let mut response = encode_response(response);
                                    self.transport_stream.write_all_buf(&mut response).await?;
                                    return Ok(None);
                                }
                            }
                        }
                        State::RequestInProgress(x) => {
                            x.buffer = BytesMut::with_capacity(self.upload_buffer_size);
                            match self.upload_tx.send(bytes.freeze()).await {
                                Ok(_) => (),
                                Err(_) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
                            }
                        }
                    },
                    Err(e) => return Err(e),
                },
                r = self.download_rx.recv() => match r {
                    None => {
                        // Arbitrate the race between EOF notification and the pipe dropping
                        let eof_fired = {
                            let eof = self.download_eof.notified();
                            tokio::pin!(eof);
                            eof.enable()
                        };
                        if eof_fired {
                            self.graceful_shutdown().await?;
                            return Ok(None);
                        }
                        return Err(io::Error::from(ErrorKind::UnexpectedEof));
                    },
                    Some(mut bytes) => self.transport_stream.write_all_buf(&mut bytes).await?,
                },
                _ = self.download_eof.notified() => {
                    self.graceful_shutdown().await?;
                    return Ok(None);
                }
            }
        }
    }

    async fn graceful_shutdown(&mut self) -> io::Result<()> {
        if let Ok(mut chunk) = self.download_rx.try_recv() {
            self.transport_stream.write_all_buf(&mut chunk).await?;
        }
        self.transport_stream.flush().await?;
        let _ = self.upload_tx.reserve().await;
        self.transport_stream.shutdown().await
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http1
    }
}

impl http_codec::Stream for Stream {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.source.id.clone()
    }

    fn request(&self) -> &dyn http_codec::PendingRequest {
        &self.source
    }

    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn http_codec::PendingRequest>,
        Box<dyn http_codec::PendingRespond>,
    ) {
        (Box::new(self.source), Box::new(self.sink))
    }
}

impl http_codec::PendingRequest for StreamSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn request(&self) -> &RequestHeaders {
        &self.request
    }

    fn client_address(&self) -> io::Result<IpAddr> {
        Ok(self.client_address)
    }

    fn finalize(self: Box<Self>) -> Box<dyn pipe::Source> {
        self
    }
}

impl http_codec::PendingRespond for StreamSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn send_intermediate_response(&self, response: ResponseHeaders) -> io::Result<()> {
        log_id!(
            debug,
            self.id,
            "Sending intermediate response: {:?}",
            response
        );

        self.download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(encode_response(response))
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to put response in queue: {}", e),
                )
            })
    }

    fn send_response(
        mut self: Box<Self>,
        mut response: ResponseHeaders,
        eof: bool,
    ) -> io::Result<Box<dyn http_codec::RespondedStreamSink>> {
        if self.insert_connection_close && !response.headers.contains_key("Connection") {
            response
                .headers
                .insert("Connection", http::HeaderValue::from_static("close"));
        }
        log_id!(
            debug,
            self.id,
            "Sending response: {:?} (eof={})",
            response,
            eof
        );

        self.download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(encode_response(response))
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to put response in queue: {}", e),
                )
            })?;

        if eof {
            self.eof()?;
        }

        Ok(self)
    }
}

impl State {
    fn take_buffer(&mut self) -> BytesMut {
        match self {
            State::WaitingRequest(x) => std::mem::take(&mut x.buffer),
            State::RequestInProgress(x) => std::mem::take(&mut x.buffer),
        }
    }
}

#[async_trait]
impl pipe::Source for StreamSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        match self.upload_rx.recv().await {
            None => Ok(pipe::Data::Eof),
            Some(bytes) => Ok(pipe::Data::Chunk(bytes)),
        }
    }

    fn consume(&mut self, _size: usize) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

impl http_codec::RespondedStreamSink for StreamSink {
    fn into_pipe_sink(self: Box<Self>) -> Box<dyn Sink> {
        self
    }

    fn into_datagram_sink(self: Box<Self>) -> Box<dyn http_codec::DroppingSink> {
        self
    }
}

#[async_trait]
impl Sink for StreamSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn write(&mut self, data: Bytes) -> io::Result<Bytes> {
        match self
            .download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(data)
        {
            Ok(_) => Ok(Bytes::new()),
            Err(mpsc::error::TrySendError::Full(unsent)) => Ok(unsent),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(ErrorKind::UnexpectedEof))
            }
        }
    }

    fn eof(&mut self) -> io::Result<()> {
        self.download_eof.notify_one();
        Ok(())
    }

    async fn wait_writable(&mut self) -> io::Result<()> {
        match self
            .download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .reserve()
            .await
        {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
        }
    }
}

impl http_codec::DroppingSink for StreamSink {
    fn write(&mut self, data: Bytes) -> io::Result<datagram_pipe::SendStatus> {
        match self
            .download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(data)
        {
            Ok(_) => Ok(datagram_pipe::SendStatus::Sent),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(datagram_pipe::SendStatus::Dropped),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(ErrorKind::UnexpectedEof))
            }
        }
    }
}

fn version_minor_digit(v: http::Version) -> u32 {
    match v {
        http::Version::HTTP_10 => 0,
        http::Version::HTTP_11 => 1,
        _ => unreachable!(),
    }
}

fn httparse_to_http_version(v: u8) -> http::Version {
    match v {
        0 => http::Version::HTTP_10,
        1 => http::Version::HTTP_11,
        _ => unreachable!(),
    }
}

fn encode_headers(mut buffer: BytesMut, headers: &http::HeaderMap<http::HeaderValue>) -> BytesMut {
    for (name, value) in headers {
        buffer.put(name.as_ref());
        buffer.put(": ".as_bytes());
        buffer.put(value.as_bytes());
        buffer.put("\r\n".as_bytes());
    }
    buffer.put("\r\n".as_bytes());

    buffer
}

pub(crate) fn encode_request(request: &RequestHeaders) -> Bytes {
    let mut encoded = BytesMut::new();

    encoded.put(request.method.as_str().as_bytes());
    encoded.put([b' '].as_slice());
    encoded.put(
        request
            .uri
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            .unwrap_or("/")
            .as_bytes(),
    );
    encoded.put(" HTTP/1.".as_bytes());
    encoded.put([('0' as u32 + version_minor_digit(request.version)) as u8].as_slice());
    encoded.put("\r\n".as_bytes());

    if let Some(host) = request.uri.authority() {
        encoded.put("Host: ".as_bytes());
        encoded.put(host.as_str().as_bytes());
        encoded.put("\r\n".as_bytes());
    }

    encoded = encode_headers(encoded, &request.headers);

    encoded.freeze()
}

pub(crate) fn encode_response(response: ResponseHeaders) -> Bytes {
    let mut encoded = BytesMut::new();

    encoded.put("HTTP/1.".as_bytes());
    encoded.put([('0' as u32 + version_minor_digit(response.version)) as u8].as_slice());
    encoded.put([b' '].as_slice());
    encoded.put(response.status.as_str().as_bytes());
    encoded.put([b' '].as_slice());
    encoded.put(
        response
            .status
            .canonical_reason()
            .unwrap_or_default()
            .as_bytes(),
    );
    encoded.put("\r\n".as_bytes());

    encoded = encode_headers(encoded, &response.headers);

    encoded.freeze()
}

pub(crate) fn decode_request(
    mut buffer: BytesMut,
    headers_num_cap: usize,
    raw_buffer_cap: usize,
) -> io::Result<DecodeStatus<RequestHeaders>> {
    let mut headers = vec![httparse::EMPTY_HEADER; headers_num_cap];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(&buffer) {
        Ok(httparse::Status::Complete(idx)) => {
            let mut request_builder = http::request::Request::builder()
                .version(httparse_to_http_version(request.version.ok_or_else(
                    || io::Error::new(ErrorKind::Other, "Version not found"),
                )?))
                .method(
                    request
                        .method
                        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Method not found"))?,
                );

            let mut uri = match request.path {
                None => {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        format!("Invalid path: {:?}", request.path),
                    ))
                }
                Some(p) => match http::uri::Uri::from_str(p) {
                    Ok(uri) => uri,
                    Err(e) => {
                        return Err(io::Error::new(
                            ErrorKind::Other,
                            format!("Invalid path: path={:?}, error={}", request.path, e),
                        ))
                    }
                },
            };

            for h in request.headers {
                match h.name.to_lowercase().as_str() {
                    "host" if uri.authority().is_none() => {
                        uri = http::uri::Uri::builder()
                            .scheme("https")
                            .authority(h.value)
                            .path_and_query(request.path.unwrap())
                            .build()
                            .map_err(|e| {
                                io::Error::new(
                                    ErrorKind::Other,
                                    format!(
                                        "Unexpected URI: error={}, authority={}, path={:?}",
                                        e,
                                        utils::hex_dump(h.value),
                                        request.path,
                                    ),
                                )
                            })?
                    }
                    _ => request_builder = request_builder.header(h.name, h.value),
                }
            }

            request_builder = request_builder.uri(uri);

            Ok(DecodeStatus::Complete(
                request_builder
                    .body(())
                    .map_err(|e| {
                        io::Error::new(ErrorKind::Other, format!("Invalid request: {}", e))
                    })?
                    .into_parts()
                    .0,
                buffer.split_off(idx),
            ))
        }
        Ok(httparse::Status::Partial) if buffer.len() < raw_buffer_cap => {
            Ok(DecodeStatus::Partial(buffer))
        }
        Ok(httparse::Status::Partial) => Err(io::Error::new(
            ErrorKind::Other,
            "Too long HTTP request headers",
        )),
        Err(e) => Err(io::Error::new(ErrorKind::Other, e.to_string())),
    }
}

pub(crate) fn decode_response(
    mut buffer: BytesMut,
    headers_num_cap: usize,
    raw_buffer_cap: usize,
) -> io::Result<DecodeStatus<ResponseHeaders>> {
    let mut headers = vec![httparse::EMPTY_HEADER; headers_num_cap];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(&buffer) {
        Ok(httparse::Status::Complete(idx)) => {
            let mut response_builder = http::response::Response::builder()
                .version(httparse_to_http_version(response.version.ok_or_else(
                    || io::Error::new(ErrorKind::Other, "Version not found"),
                )?))
                .status(
                    response
                        .code
                        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Status not found"))?,
                );

            for h in response.headers {
                response_builder = response_builder.header(h.name, h.value)
            }

            Ok(DecodeStatus::Complete(
                response_builder
                    .body(())
                    .map_err(|e| {
                        io::Error::new(ErrorKind::Other, format!("Invalid response: {}", e))
                    })?
                    .into_parts()
                    .0,
                buffer.split_off(idx),
            ))
        }
        Ok(httparse::Status::Partial) if buffer.len() < raw_buffer_cap => {
            Ok(DecodeStatus::Partial(buffer))
        }
        Ok(httparse::Status::Partial) => Err(io::Error::new(
            ErrorKind::Other,
            "Too long HTTP response headers",
        )),
        Err(e) => Err(io::Error::new(ErrorKind::Other, e.to_string())),
    }
}
