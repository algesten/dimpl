use std::ops::Deref;

macro_rules! wrapped_slice {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<'a>(pub &'a [u8]);

        impl<'a> Deref for $name<'a> {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                self.0
            }
        }
    };
}

wrapped_slice!(Asn1Cert);
wrapped_slice!(DistinguishedName);
wrapped_slice!(PublicKeyEncrypted);
