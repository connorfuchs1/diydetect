mod sensors;

use sensors::SensorConfig;


#[tokio::main]
async fn main() {
    let cfg = SensorConfig 
    {
        duration_secs: 1000,
    };

    println!("Starting sensor with config: {:?}", cfg);

    let process_task = {
        let cfg = cfg.clone();
        tokio::task::spawn_blocking( move || {
        sensors::process::run_process_sensor(&cfg);
        } )  
    };


    //TODO:
    sensors::net::run_net_sensor(&cfg);
    sensors::file::run_file_sensor(&cfg);


}
