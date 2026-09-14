pub const INDEX_HTML: &str = include_str!("assets/index.html");
pub const APP_CSS: &str = include_str!("assets/app.css");
pub const APP_JS: &str = include_str!("assets/app.js");
pub const FAVICON_SVG: &str = include_str!("assets/favicon.svg");

pub enum StaticAsset {
    Html(&'static str),
    Css(&'static str),
    Js(&'static str),
    Svg(&'static str),
}

impl StaticAsset {
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Html(_) => "text/html; charset=utf-8",
            Self::Css(_) => "text/css; charset=utf-8",
            Self::Js(_) => "application/javascript; charset=utf-8",
            Self::Svg(_) => "image/svg+xml",
        }
    }

    pub fn bytes(&self) -> &'static [u8] {
        match self {
            Self::Html(s) => s.as_bytes(),
            Self::Css(s) => s.as_bytes(),
            Self::Js(s) => s.as_bytes(),
            Self::Svg(s) => s.as_bytes(),
        }
    }
}

pub fn get_static_asset(path: &str) -> Option<StaticAsset> {
    match path {
        "/" | "/index.html" => Some(StaticAsset::Html(INDEX_HTML)),
        "/assets/app.css" => Some(StaticAsset::Css(APP_CSS)),
        "/assets/app.js" => Some(StaticAsset::Js(APP_JS)),
        "/assets/favicon.svg" | "/favicon.ico" => Some(StaticAsset::Svg(FAVICON_SVG)),
        _ => None,
    }
}
