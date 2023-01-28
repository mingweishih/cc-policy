// Copyright (c) Cc-Policy Authors.
// Licensed under the Apache 2.0 license.

#[macro_export]
macro_rules! loc {
    () => {
        concat!(file!(), " line ", line!(), " column ", column!())
    };
}
