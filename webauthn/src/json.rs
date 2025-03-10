use anyhow::anyhow;
use serde_json::Value;

pub struct ValueWrapper<'a> {
    value: &'a Value,
    base: &'a str,
}

impl<'a> ValueWrapper<'a> {
    pub fn new(value: &'a Value, base: &'a str) -> Self {
        ValueWrapper { value, base }
    }
    pub fn str(&'a self, key: &str) -> Result<&'a str, anyhow::Error> {
        match &self.value[key] {
            Value::String(s) => Ok(s),
            _ => {
                let path = format!("{}.{}", self.base, key);
                Err(anyhow::anyhow!("Value at '{path}' is not a String"))
            }
        }
    }

    // remove the cfg(test) when we re-introduce cross-origin to the using code base
    pub fn bool(&self, key: &str) -> Result<bool, anyhow::Error> {
        match &self.value[key] {
            Value::Bool(b) => Ok(*b),
            _ => {
                let path = format!("{}.{}", self.base, key);
                Err(anyhow!("Value at '{path}' is not a bool"))
            }
        }
    }

    pub fn num(&self, key: &str) -> Result<i32, anyhow::Error> {
        if let Value::Number(i) = &self.value[key] {
            if let Some(i) = i.as_i64() {
                if let Ok(i) = i32::try_from(i) {
                    return Ok(i);
                }
            }
        };
        let path = format!("{}.{}", self.base, key);
        Err(anyhow!("Value at '{path}' is not a i32 compatible number"))
    }
}

#[cfg(test)]
mod tests {
    use super::ValueWrapper;
    use anyhow::Error;
    use serde_json::json;

    #[test]
    fn test_str() -> Result<(), Error> {
        let value = json!({"a": "b"});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        assert_eq!("b", vw.str("a")?);

        let value = json!({"a": true});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.str("a");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.a' is not a String"
        );

        let value = json!({"a": true});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.str("does_not_exist");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.does_not_exist' is not a String"
        );
        Ok(())
    }

    #[test]
    fn test_bool() -> Result<(), Error> {
        let value = json!({"a": true});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        assert!(vw.bool("a")?);

        let value = json!({"a": "string"});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.bool("a");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.a' is not a bool"
        );

        let value = json!({"a": true});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.bool("does_not_exist");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.does_not_exist' is not a bool"
        );
        Ok(())
    }

    #[test]
    fn test_num() -> Result<(), Error> {
        let value = json!({"a": -8});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        assert_eq!(-8, vw.num("a")?);

        let value = json!({"a": "string"});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.num("a");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.a' is not a i32 compatible number"
        );

        let value = json!({"a": true});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.num("does_not_exist");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.does_not_exist' is not a i32 compatible number"
        );

        // larger number than 2<<32
        let i: i64 = 2 << 33;
        let value = json!({"a": i});
        let vw = ValueWrapper {
            value: &value,
            base: "outer",
        };
        let result = vw.num("a");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Value at 'outer.a' is not a i32 compatible number"
        );
        Ok(())
    }
}
