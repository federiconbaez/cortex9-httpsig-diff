/// An HTTP request as seen by the verifier.
///
/// `path` and `query` are kept exactly as they appear in the request line
/// (no decoding, no normalization). `headers` keeps every field line in
/// order, with its raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub scheme: String,
    /// Authority as received (Host header / `:authority`).
    pub authority: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn new(
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        query: Option<&str>,
    ) -> Self {
        Request {
            method: method.into(),
            scheme: scheme.into(),
            authority: authority.into(),
            path: path.into(),
            query: query.map(str::to_owned),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Raw values of every field line named `name` (case-insensitive).
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Request target in origin form.
    pub fn request_target(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }

    /// Target URI assembled from scheme, authority, path and query.
    pub fn target_uri(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme,
            self.authority,
            self.request_target()
        )
    }

    /// Remove every field line named `name`.
    pub fn without(mut self, name: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self
    }

    /// Replace every field line named `name` by one line with `value`.
    pub fn set(self, name: &str, value: &str) -> Self {
        self.without(name).header(name, value)
    }
}
