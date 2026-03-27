use std::io::Cursor;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rss::Channel;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    config::PypiConfig,
    event::{Ecosystem, PackageReleaseEvent},
    sources::{PackageSource, sleep_or_shutdown},
    state::{FileStateStore, RecentKeys, RecentKeysState},
};

const PYPI_UPDATES_URL: &str = "https://pypi.org/rss/updates.xml";
const PYPI_XMLRPC_URL: &str = "https://pypi.org/pypi";
const STATE_KEY: &str = "pypi";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PypiState {
    warmed_up: bool,
    #[serde(default)]
    last_serial: Option<u64>,
    #[serde(default)]
    recent_release_keys: RecentKeysState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PypiJournalEntry {
    package: String,
    version: String,
    timestamp: i64,
    action: String,
    serial: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum XmlRpcValue {
    Int(i64),
    String(String),
    Array(Vec<XmlRpcValue>),
}

pub struct PypiSource {
    http: reqwest::Client,
    tx: mpsc::Sender<PackageReleaseEvent>,
    state_store: FileStateStore,
    shutdown: CancellationToken,
    config: PypiConfig,
    once: bool,
}

impl PypiSource {
    pub fn new(
        http: reqwest::Client,
        tx: mpsc::Sender<PackageReleaseEvent>,
        state_store: FileStateStore,
        shutdown: CancellationToken,
        config: PypiConfig,
        once: bool,
    ) -> Self {
        Self {
            http,
            tx,
            state_store,
            shutdown,
            config,
            once,
        }
    }

    async fn fetch_events(&self) -> Result<Vec<PackageReleaseEvent>> {
        let body = self
            .http
            .get(PYPI_UPDATES_URL)
            .send()
            .await
            .context("failed to fetch PyPI updates feed")?
            .error_for_status()
            .context("PyPI updates feed returned an error")?
            .bytes()
            .await
            .context("failed to read PyPI updates feed body")?;

        let channel =
            Channel::read_from(Cursor::new(body)).context("failed to parse PyPI RSS feed")?;
        let mut events = channel
            .items()
            .iter()
            .filter_map(parse_feed_item)
            .collect::<Vec<_>>();
        events.sort_by_key(|event| event.published_at);
        Ok(events)
    }

    async fn fetch_last_serial(&self) -> Result<u64> {
        let body = self
            .http
            .post(PYPI_XMLRPC_URL)
            .header(reqwest::header::CONTENT_TYPE, "text/xml")
            .body(xmlrpc_request("changelog_last_serial", &[]))
            .send()
            .await
            .context("failed to fetch PyPI changelog last serial")?
            .error_for_status()
            .context("PyPI changelog last serial returned an error")?
            .text()
            .await
            .context("failed to read PyPI changelog last serial body")?;

        parse_xmlrpc_scalar_i64(&body)
            .and_then(|value| u64::try_from(value).ok())
            .context("failed to parse PyPI changelog last serial")
    }

    async fn fetch_journal_events_since(&self, since_serial: u64) -> Result<Vec<PypiJournalEntry>> {
        let body = self
            .http
            .post(PYPI_XMLRPC_URL)
            .header(reqwest::header::CONTENT_TYPE, "text/xml")
            .body(xmlrpc_request(
                "changelog_since_serial",
                &[XmlRpcValue::Int(
                    i64::try_from(since_serial).context("since_serial exceeds i64 range")?,
                )],
            ))
            .send()
            .await
            .context("failed to fetch PyPI changelog entries")?
            .error_for_status()
            .context("PyPI changelog entries returned an error")?
            .text()
            .await
            .context("failed to read PyPI changelog entries body")?;

        parse_pypi_changelog_entries(&body)
    }
}

#[async_trait]
impl PackageSource for PypiSource {
    fn name(&self) -> &'static str {
        "pypi"
    }

    async fn run(self: Box<Self>) -> Result<()> {
        let mut state = self
            .state_store
            .load::<PypiState>(STATE_KEY)
            .await?
            .unwrap_or_default();
        let mut recent_keys = RecentKeys::from_state(
            state.recent_release_keys.clone(),
            self.config.recent_key_capacity,
        );

        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }

            if !state.warmed_up {
                match self.fetch_last_serial().await {
                    Ok(last_serial) => {
                        if let Ok(feed_events) = self.fetch_events().await {
                            for event in &feed_events {
                                recent_keys.insert(event.release_key());
                            }
                        }
                        state.warmed_up = true;
                        state.last_serial = Some(last_serial);
                        state.recent_release_keys = recent_keys.snapshot();
                        self.state_store.save(STATE_KEY, &state).await?;
                        info!(
                            primed = recent_keys.len(),
                            last_serial, "initialized PyPI serial journal state"
                        );
                        if self.once {
                            return Ok(());
                        }
                        if sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(error) => {
                        warn!(error = %error, "PyPI serial bootstrap failed; falling back to RSS");
                    }
                }

                let events = match self.fetch_events().await {
                    Ok(events) => events,
                    Err(error) => {
                        warn!(error = %error, "PyPI RSS bootstrap failed");
                        if self.once
                            || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await
                        {
                            return Ok(());
                        }
                        continue;
                    }
                };

                for event in &events {
                    recent_keys.insert(event.release_key());
                }
                state.warmed_up = true;
                state.recent_release_keys = recent_keys.snapshot();
                self.state_store.save(STATE_KEY, &state).await?;
                info!(
                    primed = recent_keys.len(),
                    "initialized PyPI dedupe window from current feed"
                );
                if self.once {
                    return Ok(());
                }
                if sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await {
                    return Ok(());
                }
                continue;
            }

            if let Some(last_serial) = state.last_serial {
                match self.fetch_journal_events_since(last_serial).await {
                    Ok(entries) => {
                        let mut emitted = 0usize;
                        let mut max_serial = last_serial;
                        for entry in entries {
                            max_serial = max_serial.max(entry.serial);
                            if let Some(event) = journal_entry_to_event(&entry) {
                                let release_key = event.release_key();
                                if recent_keys.insert(release_key) {
                                    self.tx
                                        .send(event)
                                        .await
                                        .context("PyPI output channel closed")?;
                                    emitted += 1;
                                }
                            }
                        }

                        state.last_serial = Some(max_serial);
                        state.recent_release_keys = recent_keys.snapshot();
                        self.state_store.save(STATE_KEY, &state).await?;
                        debug!(
                            emitted,
                            last_serial = max_serial,
                            "processed PyPI serial journal"
                        );

                        if self.once
                            || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await
                        {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(error) => {
                        warn!(error = %error, "PyPI serial poll failed; falling back to RSS");
                    }
                }
            }

            let events = match self.fetch_events().await {
                Ok(events) => events,
                Err(error) => {
                    warn!(error = %error, "PyPI RSS poll failed");
                    if self.once
                        || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await
                    {
                        return Ok(());
                    }
                    continue;
                }
            };

            let mut emitted = 0usize;
            for event in events {
                let release_key = event.release_key();
                if recent_keys.insert(release_key) {
                    self.tx
                        .send(event)
                        .await
                        .context("PyPI output channel closed")?;
                    emitted += 1;
                }
            }

            debug!(emitted, "processed PyPI updates feed");
            state.recent_release_keys = recent_keys.snapshot();
            self.state_store.save(STATE_KEY, &state).await?;

            if self.once || sleep_or_shutdown(&self.shutdown, self.config.poll_interval).await {
                return Ok(());
            }
        }
    }
}

fn parse_feed_item(item: &rss::Item) -> Option<PackageReleaseEvent> {
    let release_url = item.link()?.to_string();
    let parsed = reqwest::Url::parse(&release_url).ok()?;
    let segments = parsed.path_segments()?.collect::<Vec<_>>();
    if segments.len() < 4 || segments.first().copied()? != "project" {
        return None;
    }

    let package = segments.get(1)?.to_string();
    let version = segments.get(2)?.to_string();
    let published_at = item.pub_date().and_then(parse_rfc2822);

    Some(PackageReleaseEvent {
        event_id: format!("pypi:{package}@{version}"),
        ecosystem: Ecosystem::Pypi,
        package,
        version: version.clone(),
        published_at,
        observed_at: Utc::now(),
        source: "pypi.rss.updates".to_string(),
        sequence: None,
        package_url: Some(format!("https://pypi.org/project/{}/", segments.get(1)?)),
        release_url: Some(release_url),
        metadata_url: Some(format!(
            "https://pypi.org/pypi/{}/{}/json",
            segments.get(1)?,
            version
        )),
        priority: None,
    })
}

fn parse_rfc2822(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn journal_entry_to_event(entry: &PypiJournalEntry) -> Option<PackageReleaseEvent> {
    if entry.action != "new release" || entry.package.is_empty() || entry.version.is_empty() {
        return None;
    }

    let published_at = DateTime::<Utc>::from_timestamp(entry.timestamp, 0);
    Some(PackageReleaseEvent {
        event_id: format!("pypi:{}@{}", entry.package, entry.version),
        ecosystem: Ecosystem::Pypi,
        package: entry.package.clone(),
        version: entry.version.clone(),
        published_at,
        observed_at: Utc::now(),
        source: "pypi.xmlrpc.changelog".to_string(),
        sequence: Some(entry.serial.to_string()),
        package_url: Some(format!("https://pypi.org/project/{}/", entry.package)),
        release_url: Some(format!(
            "https://pypi.org/project/{}/{}/",
            entry.package, entry.version
        )),
        metadata_url: Some(format!(
            "https://pypi.org/pypi/{}/{}/json",
            entry.package, entry.version
        )),
        priority: None,
    })
}

fn xmlrpc_request(method: &str, params: &[XmlRpcValue]) -> String {
    let mut body = String::from(r#"<?xml version="1.0"?><methodCall>"#);
    body.push_str("<methodName>");
    body.push_str(method);
    body.push_str("</methodName><params>");
    for param in params {
        body.push_str("<param>");
        encode_xmlrpc_value(&mut body, param);
        body.push_str("</param>");
    }
    body.push_str("</params></methodCall>");
    body
}

fn encode_xmlrpc_value(body: &mut String, value: &XmlRpcValue) {
    body.push_str("<value>");
    match value {
        XmlRpcValue::Int(value) => {
            body.push_str("<int>");
            body.push_str(&value.to_string());
            body.push_str("</int>");
        }
        XmlRpcValue::String(value) => {
            body.push_str("<string>");
            body.push_str(value);
            body.push_str("</string>");
        }
        XmlRpcValue::Array(values) => {
            body.push_str("<array><data>");
            for value in values {
                encode_xmlrpc_value(body, value);
            }
            body.push_str("</data></array>");
        }
    }
    body.push_str("</value>");
}

fn parse_xmlrpc_scalar_i64(body: &str) -> Option<i64> {
    let values = parse_xmlrpc_response_values(body).ok()?;
    match values.first()? {
        XmlRpcValue::Int(value) => Some(*value),
        _ => None,
    }
}

fn parse_pypi_changelog_entries(body: &str) -> Result<Vec<PypiJournalEntry>> {
    let values = parse_xmlrpc_response_values(body)?;
    let Some(XmlRpcValue::Array(entries)) = values.first() else {
        anyhow::bail!("unexpected XML-RPC changelog response");
    };

    let mut journal = Vec::new();
    for entry in entries {
        let XmlRpcValue::Array(fields) = entry else {
            continue;
        };
        if fields.len() != 5 {
            continue;
        }
        let package = xmlrpc_string(&fields[0]).unwrap_or_default();
        let version = xmlrpc_string(&fields[1]).unwrap_or_default();
        let timestamp = xmlrpc_int(&fields[2]).unwrap_or_default();
        let action = xmlrpc_string(&fields[3]).unwrap_or_default();
        let serial = xmlrpc_int(&fields[4])
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or_default();
        journal.push(PypiJournalEntry {
            package,
            version,
            timestamp,
            action,
            serial,
        });
    }
    Ok(journal)
}

fn xmlrpc_string(value: &XmlRpcValue) -> Option<String> {
    match value {
        XmlRpcValue::String(value) => Some(value.clone()),
        XmlRpcValue::Int(value) => Some(value.to_string()),
        XmlRpcValue::Array(_) => None,
    }
}

fn xmlrpc_int(value: &XmlRpcValue) -> Option<i64> {
    match value {
        XmlRpcValue::Int(value) => Some(*value),
        XmlRpcValue::String(value) => value.parse().ok(),
        XmlRpcValue::Array(_) => None,
    }
}

fn parse_xmlrpc_response_values(body: &str) -> Result<Vec<XmlRpcValue>> {
    let mut parser = XmlRpcParser::new(body);
    parser.parse_response_values()
}

struct XmlRpcParser<'a> {
    input: &'a str,
    cursor: usize,
}

impl<'a> XmlRpcParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, cursor: 0 }
    }

    fn parse_response_values(&mut self) -> Result<Vec<XmlRpcValue>> {
        if self.input.contains("<fault>") {
            anyhow::bail!("XML-RPC fault response");
        }

        let mut values = Vec::new();
        while self.find_from_cursor("<param>").is_some() {
            self.consume_until("<param>")?;
            self.consume("<param>")?;
            values.push(self.parse_value()?);
            self.consume("</param>")?;
        }
        Ok(values)
    }

    fn parse_value(&mut self) -> Result<XmlRpcValue> {
        self.consume("<value>")?;
        self.skip_ws();

        let value = if self.peek("<array>") {
            self.consume("<array>")?;
            self.consume("<data>")?;
            let mut values = Vec::new();
            loop {
                self.skip_ws();
                if self.peek("</data>") {
                    break;
                }
                values.push(self.parse_value()?);
            }
            self.consume("</data>")?;
            self.consume("</array>")?;
            XmlRpcValue::Array(values)
        } else if self.peek("<string>") {
            self.consume("<string>")?;
            let value = decode_xml_entities(self.take_until("</string>")?);
            self.consume("</string>")?;
            XmlRpcValue::String(value)
        } else if self.peek("<int>") {
            self.consume("<int>")?;
            let value = self
                .take_until("</int>")?
                .trim()
                .parse()
                .context("invalid xml-rpc int")?;
            self.consume("</int>")?;
            XmlRpcValue::Int(value)
        } else if self.peek("<i4>") {
            self.consume("<i4>")?;
            let value = self
                .take_until("</i4>")?
                .trim()
                .parse()
                .context("invalid xml-rpc i4")?;
            self.consume("</i4>")?;
            XmlRpcValue::Int(value)
        } else if self.peek("<i8>") {
            self.consume("<i8>")?;
            let value = self
                .take_until("</i8>")?
                .trim()
                .parse()
                .context("invalid xml-rpc i8")?;
            self.consume("</i8>")?;
            XmlRpcValue::Int(value)
        } else {
            let raw = decode_xml_entities(self.take_until("</value>")?);
            let trimmed = raw.trim();
            if let Ok(value) = trimmed.parse::<i64>() {
                XmlRpcValue::Int(value)
            } else {
                XmlRpcValue::String(trimmed.to_string())
            }
        };

        self.skip_ws();
        self.consume("</value>")?;
        Ok(value)
    }

    fn consume_until(&mut self, needle: &str) -> Result<()> {
        let index = self
            .find_from_cursor(needle)
            .with_context(|| format!("missing XML token {needle}"))?;
        self.cursor = index;
        Ok(())
    }

    fn take_until(&mut self, needle: &str) -> Result<&'a str> {
        let index = self
            .find_from_cursor(needle)
            .with_context(|| format!("missing XML token {needle}"))?;
        let slice = &self.input[self.cursor..index];
        self.cursor = index;
        Ok(slice)
    }

    fn consume(&mut self, expected: &str) -> Result<()> {
        self.skip_ws();
        if !self.peek(expected) {
            anyhow::bail!("expected XML token {expected}");
        }
        self.cursor += expected.len();
        Ok(())
    }

    fn peek(&self, expected: &str) -> bool {
        self.input[self.cursor..].starts_with(expected)
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.input[self.cursor..].chars().next() {
            if ch.is_whitespace() {
                self.cursor += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn find_from_cursor(&self, needle: &str) -> Option<usize> {
        self.input[self.cursor..]
            .find(needle)
            .map(|offset| self.cursor + offset)
    }
}

fn decode_xml_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pypi_release_item() {
        let item = rss::ItemBuilder::default()
            .link("https://pypi.org/project/example-package/1.2.3/".to_string())
            .pub_date("Tue, 25 Mar 2026 10:00:00 GMT".to_string())
            .build();

        let event = parse_feed_item(&item).expect("event");
        assert_eq!(event.package, "example-package");
        assert_eq!(event.version, "1.2.3");
        assert_eq!(event.event_id, "pypi:example-package@1.2.3");
    }

    #[test]
    fn parses_xmlrpc_last_serial() {
        let body = r#"<?xml version="1.0"?>
<methodResponse><params><param><value><int>24891357</int></value></param></params></methodResponse>"#;
        assert_eq!(parse_xmlrpc_scalar_i64(body), Some(24_891_357));
    }

    #[test]
    fn parses_xmlrpc_changelog_entries() {
        let body = r#"<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array><data>
          <value><array><data>
            <value><string>openllm</string></value>
            <value><string>0.4.33.dev3</string></value>
            <value><int>1701280908</int></value>
            <value><string>new release</string></value>
            <value><int>4601225</int></value>
          </data></array></value>
          <value><array><data>
            <value><string>openllm</string></value>
            <value><string>0.4.33.dev3</string></value>
            <value><int>1701280908</int></value>
            <value><string>add py3 file openllm-0.4.33.dev3-py3-none-any.whl</string></value>
            <value><int>4601226</int></value>
          </data></array></value>
        </data></array>
      </value>
    </param>
  </params>
</methodResponse>"#;

        let entries = parse_pypi_changelog_entries(body).expect("entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].package, "openllm");
        assert_eq!(entries[0].version, "0.4.33.dev3");
        assert_eq!(entries[0].action, "new release");
        assert_eq!(entries[0].serial, 4_601_225);
    }

    #[test]
    fn converts_new_release_journal_entry_to_event() {
        let entry = PypiJournalEntry {
            package: "telnyx".to_string(),
            version: "4.87.2".to_string(),
            timestamp: 1_711_234_567,
            action: "new release".to_string(),
            serial: 24_891_357,
        };

        let event = journal_entry_to_event(&entry).expect("event");
        assert_eq!(event.event_id, "pypi:telnyx@4.87.2");
        assert_eq!(event.source, "pypi.xmlrpc.changelog");
        assert_eq!(event.sequence.as_deref(), Some("24891357"));
    }

    #[test]
    fn ignores_non_release_journal_actions() {
        let entry = PypiJournalEntry {
            package: "telnyx".to_string(),
            version: "4.87.2".to_string(),
            timestamp: 1_711_234_567,
            action: "remove release".to_string(),
            serial: 24_891_358,
        };

        assert!(journal_entry_to_event(&entry).is_none());
    }
}
