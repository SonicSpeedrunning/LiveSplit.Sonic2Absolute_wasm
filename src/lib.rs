#![no_std]
use asr::{signature::Signature, timer, timer::TimerState, watcher::Watcher, Address, Process};

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

static AUTOSPLITTER: spinning_top::Spinlock<State> = spinning_top::const_spinlock(State {
    game: None,
    watchers: Watchers {
        state: Watcher::new(),
        levelid: Watcher::new(),
        startindicator: Watcher::new(),
        zoneselectongamecomplete: Watcher::new(),
        zoneindicator: Watcher::new(),
    },
    settings: None,
});

struct State {
    game: Option<ProcessInfo>,
    watchers: Watchers,
    settings: Option<Settings>,
}

struct ProcessInfo {
    game: Process,
    main_module_base: Address,
    main_module_size: u64,
    addresses: Option<MemoryPtr>,
}

struct Watchers {
    state: Watcher<u8>,
    levelid: Watcher<Acts>,
    startindicator: Watcher<u8>,
    zoneselectongamecomplete: Watcher<u8>,
    zoneindicator: Watcher<ZoneIndicator>,
}

struct MemoryPtr {
    state: Address,
    levelid: Address,
    startindicator: Address,
    zoneselectongamecomplete: Address,
    zoneindicator: Address,
}

#[derive(asr::Settings)]
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

impl State {
    fn attach_process() -> Option<ProcessInfo> {
        const PROCESS_NAMES: [&str; 1] = ["Sonic2Absolute.exe"];
        let mut proc: Option<Process> = None;
        let mut proc_name: Option<&str> = None;

        for name in PROCESS_NAMES {
            proc = Process::attach(name);
            if proc.is_some() {
                proc_name = Some(name);
                break;
            }
        }
    
        let game = proc?;
        let main_module_base = game.get_module_address(proc_name?).ok()?;
        let main_module_size: u64 = game.get_module_size(proc_name?).ok()?;
        let addresses = MemoryPtr::new(&game, main_module_base, main_module_size);

        Some(ProcessInfo {
            game,
            main_module_base,
            main_module_size,
            addresses,
        })
    }

    fn update(&mut self) {
        self.settings.get_or_insert_with(Settings::register);
        
        // Checks is LiveSplit is currently attached to a target process and runs attach_process() otherwise
        if self.game.is_none() {
            self.game = State::attach_process()
        }
        let Some(game) = &mut self.game else { return };

        if !game.game.is_open() {
            self.game = None;
            return;
        }

        // Get memory addresses
        let Some(addresses) = &game.addresses else { game.addresses = MemoryPtr::new(&game.game, game.main_module_base, game.main_module_size); return; };

        // Update the watchers variables
        let game = &game.game;
        update_internal(game, addresses, &mut self.watchers);

        let timer_state = timer::state();
        if timer_state == TimerState::Running || timer_state == TimerState::Paused {
        /*
            if is_loading(self) {
                timer::pause_game_time()
            } else {
                timer::resume_game_time()
            }
        */

        //  timer::set_game_time(game_time());
            if reset(self) {
                timer::reset()
            } else if split(self) {
                timer::split()
            }
            
        } 

        if timer_state == TimerState::NotRunning {
            if start(self) {
                timer::start();
            }
        }     
    }    
}

impl MemoryPtr {
    fn new(process: &Process, addr: Address, size: u64) -> Option<Self> {
        fn pointerpath(process: &Process, ptr: Address, offset1: u32, offset2: u32, offset3: u32) -> Option<Address> {
            let result = process.read_pointer_path32::<u32>(ptr.0 as u32, &[offset1, offset2]).ok()?;
            Some(Address(result as u64 + offset3 as u64))
        }

        const SIG: Signature<19> = Signature::new("3D ???????? 0F 87 ???????? FF 24 85 ???????? A1");
        let ptr = SIG.scan_process_range(process, addr, size)?.0 + 14;
        let ptr = Address(process.read::<u32>(Address(ptr)).ok()? as u64);
        let state = pointerpath(process, ptr, 0x4 * 89, 8, 0x9D8)?;
        let levelid = pointerpath(process, ptr, 0x4 * 123, 1, 0)?;
        let startindicator = pointerpath(process, ptr, 0x4 * 30, 8, 0x9D8)?;
        let zoneselectongamecomplete = pointerpath(process, ptr, 0x4  * 91, 8, 0x9D8)?;
        
        const SIG2: Signature<11> = Signature::new("69 F8 ???????? B8 ????????");
        let ptr = SIG2.scan_process_range(process, addr, size)?.0 + 7;
        let zoneindicator = Address(process.read::<u32>(Address(ptr)).ok()? as u64);


        Some(Self {
            state,
            levelid,
            startindicator,
            zoneselectongamecomplete,
            zoneindicator,
        })
    }
}

#[no_mangle]
pub extern "C" fn update() {
    AUTOSPLITTER.lock().update();
}

fn update_internal(game: &Process, addresses: &MemoryPtr, watchers: &mut Watchers) {
    let Some(_thing) = watchers.state.update(game.read(addresses.state).ok()) else { return };
    let Some(_thing) = watchers.startindicator.update(game.read(addresses.startindicator).ok()) else { return };
    let Some(_thing) = watchers.zoneselectongamecomplete.update(game.read(addresses.zoneselectongamecomplete).ok()) else { return };

    let Some(g) = game.read::<u32>(addresses.zoneindicator).ok() else { return };
    let i: ZoneIndicator = match &g {
        0x6E69614D => ZoneIndicator::MainMenu,
        0x656E6F5A => ZoneIndicator::Zones,
        0x69646E45 => ZoneIndicator::Ending,
        0x65766153 => ZoneIndicator::SaveSelect,
        _ => ZoneIndicator::Default
    };
    let Some(zone) = watchers.zoneindicator.update(Some(i)) else { return };

    if zone.current == ZoneIndicator::Ending {
        watchers.levelid.update(Some(Acts::Default));
    } else if zone.current == ZoneIndicator::Zones {
        let Some(g) = game.read::<u8>(addresses.levelid).ok() else { return };
        let i: Acts = match g {
            0 => Acts::EmeraldHill1,
            1 => Acts::EmeraldHill2,
            2 => Acts::ChemicalPlant1,
            3 => Acts::ChemicalPlant2,
            4 => Acts::AquaticRuin1,
            5 => Acts::AquaticRuin2,
            6 => Acts::CasinoNight1,
            7 => Acts::CasinoNight2,
            8 => Acts::HillTop1,
            9 => Acts::HillTop2,
            10 => Acts::MysticCave1,
            11 => Acts::MysticCave2,
            12 => Acts::OilOcean1,
            13 => Acts::OilOcean2,
            14 => Acts::Metropolis1,
            15 => Acts::Metropolis2,
            16 => Acts::Metropolis3,
            17 => Acts::SkyChase,
            18 => Acts::WingFortress,
            19 => Acts::DeathEgg,
            _ => Acts::Default,
        };
        watchers.levelid.update(Some(i));
    } else {
        let Some(x) = &watchers.levelid.pair else { return };
        let x = x.current;
        watchers.levelid.update(Some(x));
    }
}

fn start(state: &State) -> bool {
    let Some(settings) = &state.settings else { return false };

    let Some(state2) = &state.watchers.state.pair else { return false };
    let Some(startindicator) = &state.watchers.startindicator.pair else { return false };
    let Some(zoneselectongamecomplete) = &state.watchers.zoneselectongamecomplete.pair else { return false };

    let runstartedsavefile = state2.old == 5 && state2.current == 7;
    let ronstartednosavefile = state2.current == 4 && startindicator.changed() && startindicator.current == 1;
    let runstartedngp = state2.current == 6 && startindicator.changed() && startindicator.current == 1 && zoneselectongamecomplete.current == 0;

    (settings.start_clean_save && (runstartedsavefile || ronstartednosavefile)) || (settings.start_new_game_plus && runstartedngp)
}

fn split(state: &State) -> bool {
    let Some(levelid) = &state.watchers.levelid.pair else { return false };
    let Some(settings) = &state.settings else { return false };

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

fn reset(state: &State) -> bool {
    let Some(settings) = &state.settings else { return false };
    let Some(state2) = &state.watchers.state.pair else { return false };
    settings.reset && state2.old == 0 && (state2.current == 4 || state2.current == 5)
}

/*
    fn is_loading(state: &State) -> bool {
        false
    }
*/

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