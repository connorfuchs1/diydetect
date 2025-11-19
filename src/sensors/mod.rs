pub mod process;
pub mod net;
pub mod file;

#[derive (Debug, Clone)]
#[allow(dead_code)]
pub struct SensorConfig
{
    pub duration_secs: u64,
    //can later add more config options, for now the user selects duration of sensing

}