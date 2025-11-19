mod sensors;

use sensors::SensorConfig;



fn main() {
    let cfg = SensorConfig 
    {
        duration_secs: 1000,
    };

    println!("Starting sensor with config: {:?}", cfg);

    sensors::process::run_process_sensor(&cfg);
    sensors::net::run_net_sensor(&cfg);
    sensors::file::run_file_sensor(&cfg);


}
