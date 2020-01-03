#[derive(Debug, Clone)]
pub enum TupleIterator<T> {
    Empty,
    One(T),
    Two(T, T),
}

impl<T> Iterator for TupleIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        use TupleIterator::*;
        let cur = std::mem::replace(self, Empty);
        let (retval, newval) = match cur {
            Two(a, b) => (Some(a), One(b)),
            One(a) => (Some(a), Empty),
            Empty => (None, Empty),
        };
        *self = newval;
        retval
    }
}

pub mod serde_hex {
    use std::iter::FromIterator;

    use serde::de::Visitor;
    use serde::Deserializer;
    use serde::export::PhantomData;
    use serde::Serializer;

    pub fn serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer, T: AsRef<[u8]> {
        serializer.serialize_str(&hex::encode(data.as_ref()))
    }

    struct HexVisitor<T> {
        _marker: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for HexVisitor<T> where T: FromIterator<u8> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string containing only 0-9a-f")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error, {
            let v = hex::decode(v)
                .map_err(|e| E::custom(format!("{}", e)))?;
            Ok(v.into_iter().collect())
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error> where D: Deserializer<'de>, T: FromIterator<u8> {
        deserializer.deserialize_str(HexVisitor::<T> { _marker: PhantomData })
    }
}
