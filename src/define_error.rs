pub struct Wrapper<E> {
    pub error: E,
    backtrace: std::backtrace::Backtrace,
}

impl<E: std::fmt::Display> std::fmt::Display for Wrapper<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.error)
    }
}

impl<E: std::fmt::Display> std::fmt::Debug for Wrapper<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self)?;

        writeln!(f, "\nStack backtrace:")?;
        write!(f, "{}", self.backtrace)
    }
}

impl<E: std::error::Error> std::error::Error for Wrapper<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

impl<E> From<E> for Wrapper<E> {
    fn from(error: E) -> Self {
        Self {
            error,
            backtrace: std::backtrace::Backtrace::capture(),
        }
    }
}

/// Macro to generate error types and their wrappers
#[macro_export]
macro_rules! define_error {
    // Main entry point
    ($error_enum:ident {$($(#[$from: ident])? $variant:ident($type:ty)),+}) => {
        /// Unified error type for the entire project
        #[derive(Debug)]
        pub enum $error_enum {
            $($variant($type)),+
        }

        impl std::fmt::Display for $error_enum {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $($error_enum::$variant(error) => write!(f, "{}", error)),+
                }
            }
        }

        impl std::error::Error for $error_enum {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $($error_enum::$variant(_error) => {
                        define_error!(@source_branch $($from)? _error)
                    }),+
                }
            }
        }

        // Generate From implementations for each variant
        $(
            define_error!(@from_branch $error_enum $($from)? $variant($type));
        )+

        /// Result type using the unified error
        pub type Result<T> = std::result::Result<T, crate::define_error::Wrapper<$error_enum>>;
    };

    (@from_branch $error_enum:ident from $variant:ident($type:ty)) => {
        impl From<$type> for crate::define_error::Wrapper<$error_enum> {
            fn from(error: $type) -> Self {
                $error_enum::$variant(error).into()
            }
        }
    };

    (@from_branch $error_enum:ident $variant:ident($type:ty)) => {};

    (@source_branch from $error:ident) => {
        Some($error)
    };

    (@source_branch $error:ident) => {
        None
    };
}
