#![no_std]
#![feature(type_alias_impl_trait, const_async_blocks)]
#![warn(
    clippy::complexity,
    clippy::correctness,
    clippy::perf,
    clippy::style,
    clippy::undocumented_unsafe_blocks,
    rust_2018_idioms
)]

use asr::{
    file_format::pe,
    future::{next_tick, retry},
    settings::Gui,
    signature::Signature,
    timer::{self, TimerState},
    watcher::Watcher,
    Address, Address32, Process,
};

asr::panic_handler!();
asr::async_main!(nightly);

const PROCESS_NAMES: [&str; 1] = ["Sonic2Absolute.exe"];

async fn main() {
    let mut settings = Settings::register();

    loop {
        // Hook to the target process
        let process = retry(|| PROCESS_NAMES.iter().find_map(|&name| Process::attach(name))).await;

        process
            .until_closes(async {
                // Once the target has been found and attached to, set up some default watchers
                let mut watchers = Watchers::default();

                // Perform memory scanning to look for the addresses we need
                let addresses = Addresses::init(&process).await;

                loop {
                    // Splitting logic. Adapted from OG LiveSplit:
                    // Order of execution
                    // 1. update() will always be run first. There are no conditions on the execution of this action.
                    // 2. If the timer is currently either running or paused, then the isLoading, gameTime, and reset actions will be run.
                    // 3. If reset does not return true, then the split action will be run.
                    // 4. If the timer is currently not running (and not paused), then the start action will be run.
                    settings.update();
                    update_loop(&process, &addresses, &mut watchers);

                    let timer_state = timer::state();
                    if timer_state == TimerState::Running || timer_state == TimerState::Paused {
                        if reset(&watchers, &settings) {
                            timer::reset()
                        } else if split(&watchers, &settings) {
                            timer::split()
                        }
                    }

                    if timer::state() == TimerState::NotRunning && start(&watchers, &settings) {
                        timer::start();
                    }

                    next_tick().await;
                }
            })
            .await;
    }
}

#[derive(asr::settings::Gui)]
struct Settings {
    #[default = true]
    /// Start --> New Game
    start_clean_save: bool,
    #[default = true]
    /// Start --> New Game+
    start_new_game_plus: bool,
    #[default = true]
    /// Reset --> Enable automatic reset
    reset: bool,
    #[default = true]
    /// Emerald Hill Zone - Act 1
    emerald_hill_1: bool,
    #[default = true]
    /// Emerald Hill Zone - Act 2
    emerald_hill_2: bool,
    #[default = true]
    /// Chemical Plant Zone - Act 1
    chemical_plant_1: bool,
    #[default = true]
    /// Chemical Plant Zone - Act 2
    chemical_plant_2: bool,
    #[default = true]
    /// Aquatic Ruin Zone - Act 1
    aquatic_ruin_1: bool,
    #[default = true]
    /// Aquatic Ruin Zone - Act 2
    aquatic_ruin_2: bool,
    #[default = true]
    /// Casino Night Zone - Act 1
    casino_night_1: bool,
    #[default = true]
    /// Casino Night Zone - Act 2
    casino_night_2: bool,
    #[default = true]
    /// Hill Top Zone - Act 1
    hill_top_1: bool,
    #[default = true]
    /// Hill Top Zone - Act 2
    hill_top_2: bool,
    #[default = true]
    /// Mystic Cave Zone - Act 1
    mystic_cave_1: bool,
    #[default = true]
    /// Mystic Cave Zone - Act 2
    mystic_cave_2: bool,
    #[default = true]
    /// Oil Ocean Zone - Act 1
    oil_ocean_1: bool,
    #[default = true]
    /// Oil Ocean Zone - Act 2
    oil_ocean_2: bool,
    #[default = true]
    /// Metropolis Zone - Act 1
    metropolis_1: bool,
    #[default = true]
    /// Metropolis Zone - Act 2
    metropolis_2: bool,
    #[default = true]
    /// Metropolis Zone - Act 3
    metropolis_3: bool,
    #[default = true]
    /// Sky Chase Zone
    sky_chase: bool,
    #[default = true]
    /// Wing Fortress Zone
    wing_fortress: bool,
    #[default = true]
    /// Death Egg Zone
    death_egg: bool,
}

#[derive(Default)]
struct Watchers {
    state: Watcher<u8>,
    levelid: Watcher<Acts>,
    startindicator: Watcher<u8>,
    zoneselectongamecomplete: Watcher<u8>,
    zoneindicator: Watcher<ZoneIndicator>,
}

struct Addresses {
    state: Address,
    levelid: Address,
    startindicator: Address,
    zoneselectongamecomplete: Address,
    zoneindicator: Address,
}

impl Addresses {
    async fn init(process: &Process) -> Self {
        let main_module_base = retry(|| {
            PROCESS_NAMES
                .iter()
                .find_map(|&name| process.get_module_address(name).ok())
        })
        .await;
        let main_module_size =
            retry(|| pe::read_size_of_image(process, main_module_base)).await as u64;
        let main_module = (main_module_base, main_module_size);

        let pointer_path = |ptr, offset1, offset2, offset3| async move {
            let result = retry(|| {
                process
                    .read_pointer_path32::<Address32>(ptr, &[offset1, offset2])
                    .ok()
            })
            .await;
            core::convert::Into::<Address>::into(result) + offset3
        };

        let ptr = {
            const SIG: Signature<19> =
                Signature::new("3D ???????? 0F 87 ???????? FF 24 85 ???????? A1");
            let ptr = retry(|| SIG.scan_process_range(process, main_module)).await + 14;
            retry(|| process.read::<Address32>(ptr).ok()).await
        };

        let state = pointer_path(ptr, 0x4 * 89, 8, 0x9D8).await;
        let levelid = pointer_path(ptr, 0x4 * 123, 1, 0).await;
        let startindicator = pointer_path(ptr, 0x4 * 30, 8, 0x9D8).await;
        let zoneselectongamecomplete = pointer_path(ptr, 0x4 * 91, 8, 0x9D8).await;

        let ptr = {
            const SIG2: Signature<11> = Signature::new("69 F8 ?? ?? ?? ?? B8 ?? ?? ?? ??");
            retry(|| SIG2.scan_process_range(process, main_module)).await + 7
        };
        let zoneindicator: Address = retry(|| process.read::<Address32>(ptr).ok()).await.into();

        Self {
            state,
            levelid,
            startindicator,
            zoneselectongamecomplete,
            zoneindicator,
        }
    }
}

fn update_loop(game: &Process, addresses: &Addresses, watchers: &mut Watchers) {
    watchers
        .state
        .update_infallible(game.read(addresses.state).unwrap_or_default());
    watchers
        .startindicator
        .update_infallible(game.read(addresses.startindicator).unwrap_or_default());
    watchers.zoneselectongamecomplete.update_infallible(
        game.read(addresses.zoneselectongamecomplete)
            .unwrap_or_default(),
    );

    let zone = watchers.zoneindicator.update_infallible({
        match game.read::<u32>(addresses.zoneindicator) {
            Ok(0x6E69614D) => ZoneIndicator::MainMenu,
            Ok(0x656E6F5A) => ZoneIndicator::Zones,
            Ok(0x69646E45) => ZoneIndicator::Ending,
            Ok(0x65766153) => ZoneIndicator::SaveSelect,
            _ => ZoneIndicator::Default,
        }
    });

    watchers.levelid.update_infallible(match zone.current {
        ZoneIndicator::Ending => Acts::Default,
        ZoneIndicator::Zones => match game.read::<u8>(addresses.levelid) {
            Ok(0) => Acts::EmeraldHill1,
            Ok(1) => Acts::EmeraldHill2,
            Ok(2) => Acts::ChemicalPlant1,
            Ok(3) => Acts::ChemicalPlant2,
            Ok(4) => Acts::AquaticRuin1,
            Ok(5) => Acts::AquaticRuin2,
            Ok(6) => Acts::CasinoNight1,
            Ok(7) => Acts::CasinoNight2,
            Ok(8) => Acts::HillTop1,
            Ok(9) => Acts::HillTop2,
            Ok(10) => Acts::MysticCave1,
            Ok(11) => Acts::MysticCave2,
            Ok(12) => Acts::OilOcean1,
            Ok(13) => Acts::OilOcean2,
            Ok(14) => Acts::Metropolis1,
            Ok(15) => Acts::Metropolis2,
            Ok(16) => Acts::Metropolis3,
            Ok(17) => Acts::SkyChase,
            Ok(18) => Acts::WingFortress,
            Ok(19) => Acts::DeathEgg,
            _ => Acts::Default,
        },
        _ => match &watchers.levelid.pair {
            Some(x) => x.current,
            _ => Acts::Default,
        },
    });
}

fn start(watchers: &Watchers, settings: &Settings) -> bool {
    let Some(state2) = &watchers.state.pair else {
        return false;
    };
    let Some(startindicator) = &watchers.startindicator.pair else {
        return false;
    };
    let Some(zoneselectongamecomplete) = &watchers.zoneselectongamecomplete.pair else {
        return false;
    };

    let runstartedsavefile = state2.old == 5 && state2.current == 7;
    let ronstartednosavefile =
        state2.current == 4 && startindicator.changed() && startindicator.current == 1;
    let runstartedngp = state2.current == 6
        && startindicator.changed()
        && startindicator.current == 1
        && zoneselectongamecomplete.current == 0;

    (settings.start_clean_save && (runstartedsavefile || ronstartednosavefile))
        || (settings.start_new_game_plus && runstartedngp)
}

fn split(watchers: &Watchers, settings: &Settings) -> bool {
    let Some(levelid) = &watchers.levelid.pair else {
        return false;
    };

    match levelid.current {
        Acts::EmeraldHill2 => settings.emerald_hill_1 && levelid.old == Acts::EmeraldHill1,
        Acts::ChemicalPlant1 => settings.emerald_hill_2 && levelid.old == Acts::EmeraldHill2,
        Acts::ChemicalPlant2 => settings.chemical_plant_1 && levelid.old == Acts::ChemicalPlant1,
        Acts::AquaticRuin1 => settings.chemical_plant_2 && levelid.old == Acts::ChemicalPlant2,
        Acts::AquaticRuin2 => settings.aquatic_ruin_1 && levelid.old == Acts::AquaticRuin1,
        Acts::CasinoNight1 => settings.aquatic_ruin_2 && levelid.old == Acts::AquaticRuin2,
        Acts::CasinoNight2 => settings.casino_night_1 && levelid.old == Acts::CasinoNight1,
        Acts::HillTop1 => settings.casino_night_2 && levelid.old == Acts::CasinoNight2,
        Acts::HillTop2 => settings.hill_top_1 && levelid.old == Acts::HillTop1,
        Acts::MysticCave1 => settings.hill_top_2 && levelid.old == Acts::HillTop2,
        Acts::MysticCave2 => settings.mystic_cave_1 && levelid.old == Acts::MysticCave1,
        Acts::OilOcean1 => settings.mystic_cave_2 && levelid.old == Acts::MysticCave2,
        Acts::OilOcean2 => settings.oil_ocean_1 && levelid.old == Acts::OilOcean1,
        Acts::Metropolis1 => settings.oil_ocean_2 && levelid.old == Acts::OilOcean2,
        Acts::Metropolis2 => settings.metropolis_1 && levelid.old == Acts::Metropolis1,
        Acts::Metropolis3 => settings.metropolis_2 && levelid.old == Acts::Metropolis2,
        Acts::SkyChase => settings.metropolis_3 && levelid.old == Acts::Metropolis3,
        Acts::WingFortress => settings.sky_chase && levelid.old == Acts::SkyChase,
        Acts::DeathEgg => settings.wing_fortress && levelid.old == Acts::WingFortress,
        Acts::Default => settings.death_egg && levelid.old != levelid.current,
        _ => false,
    }
}

fn reset(watchers: &Watchers, settings: &Settings) -> bool {
    let Some(state2) = &watchers.state.pair else {
        return false;
    };
    settings.reset && state2.old == 0 && (state2.current == 4 || state2.current == 5)
}

#[derive(Clone, Copy, PartialEq)]
enum ZoneIndicator {
    MainMenu,
    Zones,
    Ending,
    SaveSelect,
    Default,
}

#[derive(Clone, Copy, PartialEq)]
enum Acts {
    EmeraldHill1,
    EmeraldHill2,
    ChemicalPlant1,
    ChemicalPlant2,
    AquaticRuin1,
    AquaticRuin2,
    CasinoNight1,
    CasinoNight2,
    HillTop1,
    HillTop2,
    MysticCave1,
    MysticCave2,
    OilOcean1,
    OilOcean2,
    Metropolis1,
    Metropolis2,
    Metropolis3,
    SkyChase,
    WingFortress,
    DeathEgg,
    Default,
}
