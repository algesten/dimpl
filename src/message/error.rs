use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError<T>
where
    T: fmt::Debug + Clone + Copy + PartialEq + Eq,
{
    kind: T,
    position: usize,
}

impl<T> ParseError<T>
where
    T: fmt::Debug + Clone + Copy + PartialEq + Eq,
{
    pub fn new(kind: T, position: usize) -> Self {
        ParseError { kind, position }
    }

    pub fn kind(&self) -> T {
        self.kind
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

impl<T> fmt::Display for ParseError<T>
where
    T: fmt::Debug + Clone + Copy + PartialEq + Eq,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Parse error at position {}: {:?}",
            self.position, self.kind
        )
    }
}

impl<T> std::error::Error for ParseError<T> where T: fmt::Debug + Clone + Copy + PartialEq + Eq {}
