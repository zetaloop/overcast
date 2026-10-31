use std::{
    env,
    error::Error,
    fmt,
    io::{self, Read, Seek, SeekFrom, Write},
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, de::DeserializeOwned};
use ureq::{Agent, Body, http::Response};

use crate::{
    Result,
    progress::{Progress, Step},
};

#[derive(Deserialize)]
pub struct Release {
    pub id: u64,
    pub tag_name: String,
    pub draft: bool,
    pub published_at: String,
    pub assets: Vec<Asset>,
}

#[derive(Deserialize)]
pub struct Asset {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub updated_at: String,
    pub browser_download_url: String,
}

pub fn client() -> Agent {
    Agent::config_builder()
        .user_agent(concat!("overcast/", env!("CARGO_PKG_VERSION")))
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_per_read(Some(Duration::from_secs(30)))
        .build()
        .into()
}

pub struct Reader<'a, R> {
    pub source: R,
    pub progress: &'a Progress,
}

impl<R: Read> Read for Reader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.progress.check().map_err(io::Error::other)?;
        self.source.read(buffer)
    }
}

impl<R: Seek> Seek for Reader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.source.seek(position)
    }
}

#[derive(Debug)]
struct Status {
    code: u16,
    message: String,
    delay: Option<Duration>,
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HTTP {}：{}", self.code, self.message)
    }
}

impl Error for Status {}

pub fn json<T: DeserializeOwned>(
    client: &Agent,
    url: &str,
    progress: &Progress,
    step: &Step,
) -> Result<T> {
    retry(progress, step, || {
        step.detail(url);
        let mut response = request(client, url)?;
        let reader = io::BufReader::new(Reader {
            source: response.body_mut().as_reader(),
            progress,
        });
        match serde_json::from_reader(reader) {
            Err(error) if error.is_io() => Err(io::Error::from(error).into()),
            result => Ok(result?),
        }
    })
}

pub fn request(client: &Agent, url: &str) -> Result<Response<Body>> {
    let mut request = client.get(url);
    if url.starts_with("https://api.github.com/") {
        request = request.header("Accept", "application/vnd.github+json");
        if let Some(token) = env::var_os("GH_TOKEN").or_else(|| env::var_os("GITHUB_TOKEN")) {
            let token = token.into_string().map_err(|_| "GitHub 凭据包含无效字符")?;
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }
    let mut response = request.call()?;
    if response.status().is_success() {
        return Ok(response);
    }
    let headers = response.headers();
    let delay = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .map(|time| time.duration_since(SystemTime::now()).unwrap_or_default())
                })
        })
        .or_else(|| {
            (headers
                .get("x-ratelimit-remaining")
                .and_then(|value| value.to_str().ok())
                == Some("0"))
            .then(|| {
                headers
                    .get("x-ratelimit-reset")?
                    .to_str()
                    .ok()?
                    .parse::<u64>()
                    .ok()
            })
            .flatten()
            .map(|seconds| {
                (SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
                    .duration_since(SystemTime::now())
                    .unwrap_or_default()
            })
        });
    let code = response.status().as_u16();
    let text = response.body_mut().read_to_string()?;
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| value["message"].as_str().map(str::to_owned))
        .unwrap_or(text);
    Err(Status {
        code,
        message,
        delay,
    }
    .into())
}

pub fn retry<T>(
    progress: &Progress,
    step: &Step,
    mut operation: impl FnMut() -> Result<T>,
) -> Result<T> {
    let mut backoff = Duration::from_secs(1);
    loop {
        progress.check()?;
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => {
                let Some(delay) = delay(error.as_ref(), backoff) else {
                    return Err(error);
                };
                step.detail(format!("{error}\n{:.0} 秒后重新请求", delay.as_secs_f64()));
                progress.wait(delay)?;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn delay(error: &(dyn Error + 'static), backoff: Duration) -> Option<Duration> {
    if let Some(status) = error.downcast_ref::<Status>() {
        return status.delay.map(|delay| delay.max(backoff)).or_else(|| {
            matches!(status.code, 408 | 429 | 500 | 502 | 503 | 504).then_some(backoff)
        });
    }
    if let Some(error) = error.downcast_ref::<ureq::Error>() {
        match error {
            ureq::Error::Timeout(_) | ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => {
                return Some(backoff);
            }
            ureq::Error::Io(error) | ureq::Error::Decompress(_, error) => {
                return delay(error, backoff);
            }
            _ => {}
        }
    }
    if let Some(error) = error.downcast_ref::<io::Error>() {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::NotConnected
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
        ) {
            return Some(backoff);
        }
        if let Some(inner) = error.get_ref() {
            return delay(inner, backoff);
        }
    }
    error.source().and_then(|source| delay(source, backoff))
}

pub fn copy(
    source: &mut impl Read,
    destination: &mut impl Write,
    progress: &Progress,
    step: &Step,
) -> Result<()> {
    let mut buffer = [0; 64 * 1024];
    let mut completed = 0;
    let started = Instant::now();
    loop {
        progress.check()?;
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        destination.write_all(&buffer[..count])?;
        completed += count as u64;
        step.set(completed);
        if step.sample() {
            step.detail(format!(
                "{:.1} MiB/s",
                completed as f64 / started.elapsed().as_secs_f64() / 1_048_576.0
            ));
        }
    }
    Ok(())
}
