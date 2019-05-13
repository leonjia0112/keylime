extern crate base64;
extern crate flate2;

use super::*;
use crypto::KeylimeCryptoError;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use openssl::sha::Sha256;
use serde_json::Value;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::io::Read;
use std::process::Command;
use std::process::Output;
use std::str;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tempfile::NamedTempFile;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;
const RETRY: usize = 4;

static EMPTYMASK: &'static str = "1";

//static HASH_ALG: Vec<&str> = vec!["sha1", "sha256", "sha384", "sha512"];
//static ENCRYPT_ALG: Vec<&str> = vec!["rsa", "ecc"];
//static SIGN_ALG: Vec<&str> =
//    vec!["rsassa", "rsapss", "ecdsa", "ecdaa", "ecschnorr"];

#[derive(Debug, Clone)]
struct TPM {
    tpmdata: Value,
    hash_alg: String,
    encrypt_alg: String,
    sign_alg: String,
}

impl TPM {
    pub fn new() -> TPM {
        TPM {
            tpmdata: json!(null),
            hash_alg: String::from("sha1"),
            encrypt_alg: String::from("rsa"),
            sign_alg: String::from("rsassa"),
        }
    }

    fn read_tpmdata(&mut self) -> Result<(), KeylimeTpmError> {
        self.tpmdata = File::open("tpmdata.json")
            .and_then(|f| serde_json::from_reader(f).map_err(|e| e.into()))?;
        Ok(())
    }

    fn write_tpmdata(&mut self) -> Result<(), KeylimeTpmError> {
        let mut f = File::create("tpmdata.json")?;
        let data_string: String =
            serde_json::to_string_pretty(&self.tpmdata)?;
        f.write_all(data_string.as_bytes())?;
        Ok(())
    }

    fn set_tpmdata(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<(), KeylimeTpmError> {
        match self.tpmdata.get_mut(key) {
            Some(ptr) => *ptr = json!(value),
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    format!("Key: {} is missing in tpmdata.json", key)
                        .as_str(),
                ));
            }
        };
        Ok(())
    }

    fn get_tpmdata(&self, key: &str) -> Result<String, KeylimeTpmError> {
        if self.tpmdata[key].is_null() {
            return Ok(String::new());
        }

        self.tpmdata[key].as_str().map_or_else(
            || {
                Err(KeylimeTpmError::new_tpm_rust_error(
                    "Failed to convert Value to stirng.",
                ))
            },
            |s| Ok(s.to_string()),
        )
    }

    pub fn init(
        &self,
        self_activate: bool,
        config_pw: String,
    ) -> Result<(String, String, String, String, String), KeylimeTpmError>
    {
        self.read_tpmdata()?;
        self.emulator_warning();
        self.set_password(config_pw)?;
        self.create_ek(None)?;
        self.get_pub_ek()?;

        Ok((
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ))
    }

    fn set_password(&self, config_pw: String) -> Result<(), KeylimeTpmError> {
        let owner_pw = match config_pw.as_str() {
            "generate" => self.random_password(20)?,
            _ => config_pw,
        };

        if let Err(e) = TPM::run(
            format!("tpm2_changeauth -o {} -e {}", owner_pw, owner_pw),
            None,
        ) {
            TPM::run(
                format!(
                    "tpm2_changeauth -o {} -e {} -O {} -E {}",
                    owner_pw, owner_pw, owner_pw, owner_pw
                ),
                None,
            )?;
        }

        self.set_tpmdata("owner_pw", &owner_pw)?;
        Ok(())
    }

    fn create_ek(&self, alg: Option<&str>) -> Result<(), KeylimeTpmError> {
        let asym_alg = match alg {
            None => self.encrypt_alg,
            Some(a) => a.to_string(),
        };

        let current_handle = self.get_tpmdata("ek_handle")?;
        let mut owner_pw = self.get_tpmdata("owner_pw")?;

        if curr_handle.is_empty() && owner_pw.is_empty() {
            let (ret_out, _) =
                TPM::run(format!("tpm_getcap -c handles-persistent"), None)?;
            let v: Vec<&str> = ret_out.matches(&curr_handle).collect();
            if !v.is_empty() {
                TPM::run(
                    format!(
                        "tpm2_evictcontrol -a o -c {} -P {}",
                        hex::encode(curr_handle),
                        owner_pw
                    ),
                    None,
                )?;
            }
        }

        if owner_pw.is_empty() {
            owner_pw = self.random_password(20)?;
            self.set_tpmdata("owner_pw", &owner_pw);
        }

        let ek_pw = self.random_password(20)?;
        let tf = NamedTempFile::new()?;
        let tf_path = self.temp_file_get_path(&tf)?;
        let paths: Vec<&str> = vec![tf_path];
        let (ret_out, f_out) = TPM::run(
            format!(
                "tpm2_createek -c -G {} -p {} -P {} -o {} -e {}",
                ek_asym_alg, tf_path, ek_pw, owner_pw, owner_pw
            ),
            Some(paths),
        )?;

        let ek_tpm = f_out.get(tf_path).ok_or_else(|| {
            KeylimeTpmError::new_tpm_rust_error(
                "Createek output to file content is missing",
            )
        })?;

        let ret_out_map: Value = serde_yaml::from_str(&ret_out)?;
        let persistent_handle = ret_out_map["persistent-handle"]
            .as_str()
            .unwrap_or_else(|| "");

        self.set_tpmdata("ek_handle", persistent_handle.into())?;
        self.set_tpmdata("ek_pw", &ek_pw)?;
        self.set_tpmdata("ek_tpm", &base64::encode(&ek_tpm))?;
        self.write_tpmdata()?;
        Ok(())
    }

    fn get_pub_ek(&self) -> Result<(), KeylimeTpmError> {
        let ek_handle = self.get_tpmdata("ek_handle")?;
        let tf = NamedTempFile::new()?;
        let tf_path = self.temp_file_get_path(&tf)?;
        let paths = vec![tf_path];

        let (_, ret_file_map) = self.run(
            format!(
                "tpm2_readpublic -c {} -o {} -f pem",
                hex::encode(ek_handle),
                tf_path
            ),
            Some(paths),
        )?;

        let ek = ret_file_map.get(tf_path).ok_or_else(|| {
            KeylimeTpmError::new_tpm_rust_error(
                "tpm2_readpublic fail, ek key is missing is output file.",
            )
        })?;
        self.set_tpmdata("ek", &ek);
        Ok(())
    }

    fn tpm_read_ekcert_nvram() -> Result<String, KeylimeTpmError> {
        let mut tf = NamedTempFile::new()?;
        let nvpath = self.temp_file_get_path(&tf)?;
        let (ret_out, _): (String, HashMap<String, String>) =
            run("tpm2_nvlist".to_string(), None)?;
        let ret_out_value: Value = serde_yaml::from_str(&ret_out)?;
        if ret_out_value["0x1c00002"]["size"].is_null() {
            return Err(KeylimeTpmError::new_tpm_rust_error(
                "TPM nvlist failed.",
            ));
        }

        let ekcert_size = ret_out_value["0x1c00002"]["size"].clone();
        let (_, f_out) = TPM::run(
            format!(
                "tpm2_nvread -x 0x1c00002 -s {} -f {}",
                ekcert_size, nvpath
            ),
            Some(vec![nvpath]),
        )?;
        let ekcert = f_out.get(nvpath).ok_or_else(|| {
            KeylimeTpmError::new_tpm_rust_error(
                "failed to read nvram and retrieve ekcert.",
            )
        })?;
        Ok(base64::encode(ekcert))
    }

    /// Static Public Function
    pub fn run(
        command: String,
        output_path: Option<Vec<&str>>,
    ) -> Result<(String, HashMap<String, String>), KeylimeTpmError> {
        let words: Vec<&str> = command.split(" ").collect();
        let mut number_tries = 0;
        let args = &words[1..words.len()];
        let cmd = &words[0];
        let mut env_vars: HashMap<String, String> = HashMap::new();
        for (key, value) in env::vars() {
            env_vars.insert(key.to_string(), value.to_string());
        }
        let lib_path = env_vars
            .get("LD_LIBRARY_PATH")
            .map_or_else(|| String::new(), |v| v.clone());
        env_vars.insert(
            "LD_LIBRARY_PATH".to_string(),
            format!("{}:{}", lib_path, common::TPM_LIBS_PATH),
        );
        env_vars.insert(
            "TPM2TOOLS_TCTI".to_string(),
            "tabrmd:bus_name=com.intel.tss2.Tabrmd".to_string(),
        );
        match env_vars.get_mut("PATH") {
            Some(v) => v.push_str(common::TPM_TOOLS_PATH),
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "PATH envrionment variable dosen't exist.",
                ));
            }
        }
        let mut output: Output;
        'exec: loop {
            let t0 = SystemTime::now();

            output =
                Command::new(&cmd).args(args).envs(&env_vars).output()?;

            let t_diff = t0.duration_since(t0)?;
            info!("Time cost: {}", t_diff.as_secs());
            match output.status.code() {
                Some(TPM_IO_ERROR) => {
                    number_tries += 1;
                    if number_tries >= MAX_TRY {
                        return Err(KeylimeTpmError::new_tpm_error(
                            TPM_IO_ERROR,
                            format!(
                                "{}{}{}{}",
                                "TPM appears to be in use by another ",
                                "application. Keylime is incompatible with ",
                                "with other TPM TSS application like trousers/",
                                "tpm-tools. Please uninstall or disable.",
                            )
                            .as_str(),
                        ));
                    }

                    info!(
                        "Failed to call TPM {}/{} times, try again in {}s.",
                        number_tries, MAX_TRY, RETRY,
                    );

                    thread::sleep(RETRY_SLEEP);
                }

                _ => break 'exec,
            }
        }

        let return_output = String::from_utf8(output.stdout)?;
        match output.status.code() {
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "Execution return code is None.",
                ));
            }
            Some(0) => info!("Successfully executed TPM command."),
            Some(c) => {
                return Err(KeylimeTpmError::new_tpm_error(
                    c,
                    format!(
                        "Command: {} returned {}, output {}",
                        command, c, return_output,
                    )
                    .as_str(),
                ));
            }
        }

        let mut file_output: HashMap<String, String> = HashMap::new();
        if let Some(paths) = output_path {
            for p in paths {
                file_output
                    .insert(p.into(), read_file_output_path(p.to_string())?);
            }
        }
        Ok((return_output, file_output))
    }

    /// Static Private Function
    fn read_file_output_path(output_path: String) -> std::io::Result<String> {
        let mut file = File::open(output_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }

    fn random_password(
        &self,
        length: usize,
    ) -> Result<String, KeylimeTpmError> {
        let rand_byte = crypto::generate_random_byte(&length)?;
        let alphabet: Vec<char> =
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGIJKLMNOPQRSTUVWXYZ"
                .chars()
                .collect();

        let mut password = Vec::new();
        for i in rand_byte.as_slice() {
            password.push(alphabet[*i as usize % alphabet.len()]);
        }
        let password_str: String = password.iter().collect();
        Ok(password_str)
    }

    fn temp_file_get_path<'a>(
        &self,
        ref temp_file: &'a NamedTempFile,
    ) -> Result<&'a str, KeylimeTpmError> {
        temp_file.path().to_str().ok_or_else(|| {
            KeylimeTpmError::new_tpm_rust_error(
                "Can't retrieve temp file path.",
            )
        })
    }

    fn emulator_warning(&self) {
        if is_software_tpm() {
            warn!(
                "{}{}{}{}{}{}",
                "INSECURE: Keylhme is using a software TPM emulator rather ",
                "than a real hardware TPM.",
                "INSECURE: The security of Keylime is NOT linked to a ",
                "hardware root of trust.",
                "INSECURE: Only use Keylime in this mode for testing or ",
                "debugging purposes.",
            );
        }
    }

    fn tpm_get_manufacturer() -> Option<String> {
        let (ret_out, _) =
            TPM::run("tpm2_getcap -c properties-fixed".to_string(), None)?;
        let out_to_json: Value = serde_json::from_str(&ret_out)?;
        if out_to_json["TPM_PT_VENDOR_STRING_1"]["value"].is_null() {
            return None;
        }
        Some(out_to_json["TPM_PT_VENDOR_STRING_1"]["value"].to_string());
    }

    fn is_software_tpm() -> bool {
        match tpm_get_manufacturer() {
            Some(data) => data == "SW",
            None => false,
        }
    }

    fn is_vtpm() -> bool {
        return false;
    }

    fn is_deep_quote(quote: String) -> bool {
        match &quote[0..1] {
            "d" => true,
            "r" => false,
            _ => {
                warn!("Invalid quote type {}.", quote);
                false
            }
        }
    }

}

/*
 * Custom Error type for tpm execution error. It contains both error from the
 * TPM command execution result or error cause by rust function. Potential
 * rust error are map to this error by implemented From<> trait.
 */
#[derive(Debug)]
pub enum KeylimeTpmError {
    TpmRustError { details: String },
    TpmError { code: i32, details: String },
}

impl KeylimeTpmError {
    fn new_tpm_error(err_code: i32, err_msg: &str) -> KeylimeTpmError {
        KeylimeTpmError::TpmError {
            code: err_code,
            details: err_msg.to_string(),
        }
    }

    fn new_tpm_rust_error(err_msg: &str) -> KeylimeTpmError {
        KeylimeTpmError::TpmRustError {
            details: err_msg.to_string(),
        }
    }
}

impl Error for KeylimeTpmError {
    fn description(&self) -> &str {
        match &self {
            KeylimeTpmError::TpmError {
                ref details,
                code: _,
            } => details,
            KeylimeTpmError::TpmRustError { ref details } => details,
        }
    }
}

impl fmt::Display for KeylimeTpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeylimeTpmError::TpmError {
                ref code,
                ref details,
            } => write!(
                f,
                "Execute TPM command failed with Error Code: [{}] and 
                Error Message [{}].",
                code, details,
            ),
            KeylimeTpmError::TpmRustError { ref details } => write!(
                f,
                "Error occur in TPM rust interface with message [{}].",
                details,
            ),
        }
    }
}

impl From<std::io::Error> for KeylimeTpmError {
    fn from(e: std::io::Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<std::time::SystemTimeError> for KeylimeTpmError {
    fn from(e: std::time::SystemTimeError) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<std::string::FromUtf8Error> for KeylimeTpmError {
    fn from(e: std::string::FromUtf8Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<serde_json::error::Error> for KeylimeTpmError {
    fn from(e: serde_json::error::Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<std::num::ParseIntError> for KeylimeTpmError {
    fn from(e: std::num::ParseIntError) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<serde_yaml::Error> for KeylimeTpmError {
    fn from(e: serde_yaml::Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<Box<String>> for KeylimeTpmError {
    fn from(e: Box<String>) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(&e)
    }
}

/*
 * These test are for Centos and tpm4720 elmulator install environment. It
 * test tpm command before execution.
 */
#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;

    fn test_read_file_output_path() {
        assert_eq!(
            read_file_output_path("test_input.txt".to_string()).unwrap(),
            "Hello World!\n"
        );
    }

    #[test]
    fn test_get_temp_file_path() {
        let tmp_f = NamedTempFile::new().unwrap();
        assert!(TPM::temp_file_get_path(&tmp_f).is_ok());
    }

    #[test]
    fn test_is_vtpm() {
        // placeholder vtpm working in progress
        assert!(true);
    }

    #[test]
    fn test_tpm_get_manufacturer() {
        match command_exist("tpm2_getcap") {
            true => {
                assert!(tpm_initialize().is_ok());
                assert!(tpm_get_manufacturer().is_ok());
            }
            false => assert!(true),
        }
    }

    #[test]
    fn test_zlib_encoding() {
        let bytes = base64::decode("eJzLTq3MycxN1S0qLS4BAB/wBOw=").unwrap();
        let mut z = flate2::read::ZlibDecoder::new(&bytes[..]);
        let mut s = String::new();
        z.read_to_string(&mut s).unwrap();
        assert_eq!(String::from("keylime-rust"), s);
    }

    #[test]
    fn test_run_command() {
        match command_exist("tpm2_getrandom") {
            true => {
                assert!(tpm_initialize().is_ok());
                let command = "getrandom -size 8 -out foo.out".to_string();
                run(command, None);
                let p = Path::new("foo.out");
                assert_eq!(p.exists(), true);
                fs::remove_file("foo.out").unwrap();
            }
            false => assert!(true),
        }
    }

    fn tpm_initialize() -> Result<(), KeylimeTpmError> {
        run("tpm2_startup -c".to_string(), None).map(|x| ())
    }

    #[test]
    fn test_get_tpm_metadata_1() {
        assert!(set_tpmdata_test().is_ok());

        // using test tpmdata.json content must present, system won't panic
        let remove: &[_] = &['"', ' ', '/'];
        let password = get_tpm_metadata_content("aik_handle")
            .expect("Failed to get aik_handle.");
        assert_eq!(password.trim_matches(remove), String::from("FB1F19E0"));
    }

    #[test]
    fn test_get_tpm_metadata_2() {
        assert!(set_tpmdata_test().is_ok());

        // foo is not a key in tpmdata, this call should fail
        assert_eq!(get_tpm_metadata_content("foo").unwrap(), String::new());
    }

    #[test]
    fn test_write_tpm_metadata() {
        assert!(set_tpmdata_test().is_ok());
        set_tpm_metadata_content("owner_pw", "hello")
            .expect("Failed to set owner_pw.");

        // using test tpmdata.json content must present, system won't panic
        let remove: &[_] = &['"', ' ', '/'];
        let password = get_tpm_metadata_content("owner_pw")
            .expect("Failed to get owner_pw.");
        assert_eq!(password.trim_matches(remove), String::from("hello"));
    }

    #[test]
    fn test_random_password() {
        let pw = random_password(20).unwrap();
        assert_eq!(pw.len(), 20);
    }

    /*
     * Input: command name
     * Output: checkout command result
     *
     * Look for the command in path, if command is there return true, if
     * command is not exist return false.
     */
    fn command_exist(command: &str) -> bool {
        if let Ok(path) = env::var("PATH") {
            for pp in path.split(":") {
                let command_path = format!("{}/{}", pp, command);
                if fs::metadata(command_path).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    /*
     * copy tpmdata_test.json file to tpmdata.json for testing
     */
    fn set_tpmdata_test() -> Result<(), Box<Error>> {
        let file = File::open("tpmdata_test.json")?;
        let data: Value = serde_json::from_reader(file)?;
        let mut buffer = BufWriter::new(File::create("tpmdata.json")?);
        let data_string = serde_json::to_string_pretty(&data)?;
        buffer.write(data_string.as_bytes())?;
        buffer.flush()?;
        Ok(())
    }
}
