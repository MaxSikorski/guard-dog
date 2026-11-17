//! Setup-level facts, derived from per-service facts and never stored.
//!
//! Judge B's `chain`, `platform`, `exposure`, `arch`, `block_storage`, the
//! service versions and the packages inside them all come out of
//! [`setup_view`]. It is a pure fold: the same facts in any order give the same
//! view, and anything that can't be settled is `Unknown`, never a guess.

use std::collections::BTreeMap;

use crate::fact::{
    Area, BackendKind, BlindSpotKind, CatalogId, Chain, Claim, Fact, FsKind, HintId, InstanceRef,
    Method, Observed, PackageState, PlainVersion, Presence, Reach, ServiceState, Subject, Unknown,
    UnknownReason, WordSize,
};

/// What every fact said about one setup, folded.
#[derive(Clone, Debug)]
pub struct SetupView {
    /// Judge B's `source`: one back end kind, or `Unknown(Conflict)` if mixed.
    pub source: Observed<BackendKind>,
    /// The chain the nodes are on.
    pub chain: Observed<Chain>,
    /// The platform (`docker`, `umbrelos`, ...).
    pub platform: Observed<CatalogId>,
    /// From the host's architecture.
    pub word_size: Observed<WordSize>,
    /// The file system under the block data.
    pub block_storage: Observed<FsKind>,
    /// The widest reach of any port seen; an unknown port that might reach
    /// further makes the whole answer unknown.
    pub exposure: Observed<Reach>,
    /// Each service's version, by the best detection method.
    pub services: BTreeMap<InstanceRef, Observed<PlainVersion>>,
    /// Running, stopped or not found, per service. `service_running` is read
    /// from here, never from "a fact exists".
    pub states: BTreeMap<InstanceRef, Observed<ServiceState>>,
    /// Where methods of different rank gave different versions (the better one
    /// was used). Sorted.
    pub blind_spots: Vec<ViewBlindSpot>,
    /// Keyed by (the service it is inside, the product).
    pub packages: BTreeMap<(InstanceRef, CatalogId), Observed<PackageState>>,
}

/// A note the fold raises about a service: two ways of finding its version
/// disagreed. Becomes a `BlindSpot` fact when the scan is stored.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewBlindSpot {
    pub subject: InstanceRef,
    pub area: Area,
    pub what: BlindSpotKind,
    pub hint: HintId,
}

/// Folds `facts` into one view. Order of `facts` never matters.
pub fn setup_view(facts: &[Fact]) -> SetupView {
    let mut sources = Vec::new();
    let mut states: BTreeMap<InstanceRef, Vec<Observed<ServiceState>>> = BTreeMap::new();
    let mut chains = Vec::new();
    let mut platforms = Vec::new();
    let mut word_sizes = Vec::new();
    let mut storage = Vec::new();
    let mut reaches = Vec::new();
    let mut services: BTreeMap<InstanceRef, Vec<(Method, Observed<PlainVersion>)>> =
        BTreeMap::new();
    let mut packages: BTreeMap<(InstanceRef, CatalogId), Vec<Observed<PackageState>>> =
        BTreeMap::new();

    for fact in facts {
        sources.push(Observed::Seen(fact.source.backend.kind()));
        match &fact.claim {
            Claim::Chain(chain) => chains.push(chain.clone()),
            Claim::Platform { id, .. } => platforms.push(Observed::Seen(id.clone())),
            Claim::Host { arch, .. } => word_sizes.push(match arch {
                Observed::Seen(arch) => match arch.word_size() {
                    Some(size) => Observed::Seen(size),
                    None => Observed::Unknown(Unknown::new(UnknownReason::Unparsable)),
                },
                Observed::Unknown(unknown) => Observed::Unknown(Unknown::new(unknown.reason)),
            }),
            Claim::BlockStorage(kind) => storage.push(kind.clone()),
            Claim::Exposure { reach, .. } => reaches.push(reach.clone()),
            Claim::Service {
                state,
                version,
                method,
                ..
            } => {
                if let Subject::Service(instance) = &fact.subject {
                    states
                        .entry(instance.clone())
                        .or_default()
                        .push(state.clone());
                    services
                        .entry(instance.clone())
                        .or_default()
                        .push((*method, version.clone()));
                }
            }
            Claim::Package {
                product,
                presence,
                version,
            } => {
                if let Subject::Service(instance) = &fact.subject {
                    packages
                        .entry((instance.clone(), product.clone()))
                        .or_default()
                        .push(package_state(presence, version));
                }
            }
            _ => {}
        }
    }

    let mut blind_spots = Vec::new();
    let services = services
        .into_iter()
        .map(|(instance, found)| {
            let (value, disagrees) = fold_by_method(&found);
            // The hint is a literal that always parses; if it ever stopped, the
            // note is dropped rather than panicking.
            if let (true, Ok(hint)) = (disagrees, HintId::parse("methods-disagree")) {
                blind_spots.push(ViewBlindSpot {
                    subject: instance.clone(),
                    area: Area::Services,
                    what: BlindSpotKind::MethodsDisagree,
                    hint,
                });
            }
            (instance, value)
        })
        .collect();
    blind_spots.sort();

    SetupView {
        source: fold(&sources, |a, b| a == b),
        states: states
            .into_iter()
            .map(|(instance, found)| (instance, fold(&found, |a, b| a == b)))
            .collect(),
        blind_spots,
        chain: fold(&chains, |a, b| a == b),
        platform: fold(&platforms, |a, b| a == b),
        word_size: fold(&word_sizes, |a, b| a == b),
        block_storage: fold(&storage, fs_agree),
        exposure: fold_exposure(&reaches),
        services,
        packages: packages
            .into_iter()
            .map(|(key, found)| (key, fold(&found, |a, b| a == b)))
            .collect(),
    }
}

/// An unrecognised file system counts as disagreeing even with itself, which
/// can only turn an answer into `Unknown(Conflict)`, never into a wrong value.
fn fs_agree(a: &FsKind, b: &FsKind) -> bool {
    match (a, b) {
        (FsKind::Other(_), _) | (_, FsKind::Other(_)) => false,
        (FsKind::Ext4, FsKind::Ext4)
        | (FsKind::Btrfs, FsKind::Btrfs)
        | (FsKind::Xfs, FsKind::Xfs)
        | (FsKind::Zfs, FsKind::Zfs)
        | (FsKind::F2fs, FsKind::F2fs)
        | (FsKind::Fat32, FsKind::Fat32)
        | (FsKind::Exfat, FsKind::Exfat)
        | (FsKind::Ntfs, FsKind::Ntfs)
        | (FsKind::Tmpfs, FsKind::Tmpfs) => true,
        _ => false,
    }
}

/// The reason to report when nothing was seen: the smallest, so the choice
/// doesn't depend on order. No detail text is carried over.
fn no_value<T>(unknowns: &[UnknownReason]) -> Observed<T> {
    let reason = unknowns
        .iter()
        .min()
        .copied()
        .unwrap_or(UnknownReason::NotChecked);
    Observed::Unknown(Unknown::new(reason))
}

/// Several statements about one thing. All `Seen` ones agree: that value. Two
/// that differ: `Unknown(Conflict)`. None seen: `Unknown`.
fn fold<T: Clone>(items: &[Observed<T>], agree: impl Fn(&T, &T) -> bool) -> Observed<T> {
    let mut seen = Vec::new();
    let mut unknowns = Vec::new();
    for item in items {
        match item {
            Observed::Seen(value) => seen.push(value),
            Observed::Unknown(unknown) => unknowns.push(unknown.reason),
        }
    }
    match seen.split_first() {
        Some((first, rest)) => {
            if rest.iter().all(|other| agree(first, other)) {
                Observed::Seen((*first).clone())
            } else {
                Observed::Unknown(Unknown::new(UnknownReason::Conflict))
            }
        }
        None => no_value(&unknowns),
    }
}

/// A service's version: only the best evidence counts. Among the `Seen`
/// versions found by the strongest method, they must agree.
fn fold_by_method(found: &[(Method, Observed<PlainVersion>)]) -> (Observed<PlainVersion>, bool) {
    let best = found
        .iter()
        .filter(|(_, observed)| matches!(observed, Observed::Seen(_)))
        .map(|(method, _)| *method)
        .min();
    match best {
        Some(best) => {
            let top: Vec<Observed<PlainVersion>> = found
                .iter()
                .filter(|(method, _)| *method == best)
                .map(|(_, observed)| observed.clone())
                .collect();
            let winner = fold(&top, |a, b| a == b);
            // A lower-ranked method that saw a different version is a blind spot.
            let disagrees = match &winner {
                Observed::Seen(chosen) => found.iter().any(|(method, observed)| {
                    *method != best && matches!(observed, Observed::Seen(v) if v != chosen)
                }),
                Observed::Unknown(_) => false,
            };
            (winner, disagrees)
        }
        None => {
            let reasons: Vec<UnknownReason> = found
                .iter()
                .filter_map(|(_, observed)| match observed {
                    Observed::Unknown(unknown) => Some(unknown.reason),
                    Observed::Seen(_) => None,
                })
                .collect();
            (no_value(&reasons), false)
        }
    }
}

/// A package's state from its two observations: absent, present with a
/// version, or unknown (never absent for lack of looking).
fn package_state(
    presence: &Observed<Presence>,
    version: &Observed<PlainVersion>,
) -> Observed<PackageState> {
    match (presence, version) {
        (Observed::Seen(Presence::Absent), _) => Observed::Seen(PackageState::NotInstalled),
        (Observed::Seen(Presence::Present), Observed::Seen(v)) => {
            Observed::Seen(PackageState::Version(v.clone()))
        }
        (Observed::Seen(Presence::Present), Observed::Unknown(u)) => {
            Observed::Unknown(Unknown::new(u.reason))
        }
        (Observed::Unknown(u), _) => Observed::Unknown(Unknown::new(u.reason)),
    }
}

/// The widest reach seen. Reaching the internet is settled by one sighting; any
/// lesser answer stands only if every port was actually checked.
fn fold_exposure(items: &[Observed<Reach>]) -> Observed<Reach> {
    let mut widest: Option<Reach> = None;
    let mut unknowns = Vec::new();
    for item in items {
        match item {
            Observed::Seen(reach) => widest = widest.max(Some(*reach)),
            Observed::Unknown(unknown) => unknowns.push(unknown.reason),
        }
    }
    match widest {
        Some(Reach::Internet) => Observed::Seen(Reach::Internet),
        Some(reach) if unknowns.is_empty() => Observed::Seen(reach),
        _ => no_value(&unknowns),
    }
}
