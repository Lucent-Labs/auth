//! This module contains helper functions for initializing the Auth struct
//! from `php artisan tinker` commands.
//!
//! `php artisan tinker --execute 'echo config("app.key") . "\n"'`
use crate::error::AResult;
use crate::Auth;
use std::process::Command;

impl Auth {
    /// Initializes the Auth struct from the Laravel app at the given path.
    ///
    /// Uses Tinker to pull requisite data from Laravel.
    pub fn from_tinker(laravel_path: &str) -> AResult<Self> {
        let app_key = app_key(laravel_path)?;
        let database_prefix = database_prefix(laravel_path)?;

        Auth::new(&app_key, database_prefix)
    }
}

fn app_key(path: &str) -> AResult<String> {
    Ok(tinker(path, r#"echo config('app.key') . "\n";"#)?
        .trim()
        .to_string())
}

fn database_prefix(path: &str) -> AResult<String> {
    let cache_prefix = tinker(path, r#"echo config('cache.prefix') . "\n";"#)?
        .trim()
        .to_string();

    let mut database_prefix = tinker(
        &path,
        r#"echo config('database.redis.options.prefix') . "\n";"#,
    )?
    .trim()
    .to_string();
    database_prefix.push_str(&cache_prefix);

    Ok(database_prefix)
}

fn tinker(path: &str, cmd: &str) -> AResult<String> {
    let r = Command::new("php")
        .arg("artisan")
        .arg("tinker")
        .arg("--execute")
        .arg(cmd)
        .current_dir(path)
        .output()?;

    let res = String::from_utf8(r.stdout)?;
    Ok(res)
}

#[cfg(test)]
mod from_env_test {
    use crate::error::AResult;
    use crate::Auth;

    #[test]
    #[ignore]
    fn it_works() -> AResult<()> {
        dotenv::dotenv()?;
        let laravel_path = std::env::var("LARAVEL_ENV_PATH").unwrap();
        let _ = Auth::from_tinker(&laravel_path)?;

        Ok(())
    }
}
