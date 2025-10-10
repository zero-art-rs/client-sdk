pub trait Decompose {
    type Parts;

    fn decompose(self) -> Self::Parts;
}

pub trait Compose<P> {
    fn compose(parts: P) -> Self;
}

pub trait TryDecompose {
    type Parts;
    type Error;

    fn try_decompose(self) -> Result<Self::Parts, Self::Error>;
}

pub trait TryCompose<P> {
    type Error;

    fn try_compose(parts: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
