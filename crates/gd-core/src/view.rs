//! Setup-level facts, derived from per-service facts and never stored.
//!
//! Judge B's `chain`, `platform`, `exposure`, `arch`, `block_storage`, the
//! service versions and the packages inside them all come out of
//! [`setup_view`]. It is a pure fold: the same facts in any order give the same
//! view, and anything that can't be settled is `Unknown`, never a guess.

use std::collections::{BTreeMap, BTreeSet};

use crate::fact::{
    Area, BackendKind, BlindSpotKind, CatalogId, Chain, Claim, Fact, FsKind, HintId, InstanceRef,
    Method, Observed, PackageState, PlainVersion, Presence, Reach, ServiceState, SettingId,
    SettingValue, Subject, Unknown, UnknownReason, WordSize,
};

type PackageKey = (InstanceRef, CatalogId);
type PackageFacts = Vec<(Observed<Presence>, Observed<PlainVersion>)>;

/// What every fact said about one setup, folded. The per-service maps are
/// private: ask through `service`, `state` and `package`, which answer
/// `Unknown(NotChecked)` for something no fact mentioned, never a missing value.
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
    /// Where the fold met something it could not settle quietly: methods that
    /// disagree, a better method with no answer, a claim on the wrong subject.
    /// Sorted, without repeats.
    pub blind_spots: Vec<ViewBlindSpot>,
    services: BTreeMap<InstanceRef, Observed<PlainVersion>>,
    states: BTreeMap<InstanceRef, Observed<ServiceState>>,
    packages: BTreeMap<PackageKey, Observed<PackageState>>,
    settings: BTreeMap<SettingId, Observed<SettingValue>>,
}

fn not_checked<T>() -> Observed<T> {
    Observed::Unknown(Unknown::new(UnknownReason::NotChecked))
}

impl SetupView {
    /// A service's version, by the best detection method.
    pub fn service(&self, instance: &InstanceRef) -> Observed<PlainVersion> {
        self.services
            .get(instance)
            .cloned()
            .unwrap_or_else(not_checked)
    }

    /// Running, stopped or not found. `service_running` is read from here,
    /// never from "a fact exists".
    pub fn state(&self, instance: &InstanceRef) -> Observed<ServiceState> {
        self.states
            .get(instance)
            .cloned()
            .unwrap_or_else(not_checked)
    }

    /// A package inside a service: absent, or installed.
    pub fn package(&self, inside: &InstanceRef, product: &CatalogId) -> Observed<PackageState> {
        self.packages
            .get(&(inside.clone(), product.clone()))
            .cloned()
            .unwrap_or_else(not_checked)
    }

    /// A setting (`option_enabled`, `feature_enabled`, ...): what the facts say,
    /// or `Unknown(NotChecked)` if none does. Conditions are read from here.
    pub fn setting(&self, key: &SettingId) -> Observed<SettingValue> {
        self.settings.get(key).cloned().unwrap_or_else(not_checked)
    }

    /// Every setting some fact mentioned, in order.
    pub fn settings(&self) -> impl Iterator<Item = (&SettingId, &Observed<SettingValue>)> {
        self.settings.iter()
    }

    /// Every service some fact mentioned, in order.
    pub fn services(&self) -> impl Iterator<Item = (&InstanceRef, &Observed<PlainVersion>)> {
        self.services.iter()
    }

    /// Every service whose state some fact mentioned, in order.
    pub fn states(&self) -> impl Iterator<Item = (&InstanceRef, &Observed<ServiceState>)> {
        self.states.iter()
    }

    /// Every (service, product) some fact mentioned, in order.
    pub fn packages(&self) -> impl Iterator<Item = (&PackageKey, &Observed<PackageState>)> {
        self.packages.iter()
    }
}

/// A note the fold raises. Becomes a `BlindSpot` fact when the scan is stored.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewBlindSpot {
    pub subject: Subject,
    pub area: Area,
    pub what: BlindSpotKind,
    pub hint: HintId,
}

/// The hint is a literal that always parses; if it ever stopped, the note is
/// dropped rather than panicking.
fn spot(subject: &Subject, area: Area, what: BlindSpotKind, hint: &str) -> Option<ViewBlindSpot> {
    Some(ViewBlindSpot {
        subject: subject.clone(),
        area,
        what,
        hint: HintId::parse(hint).ok()?,
    })
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
    let mut packages: BTreeMap<PackageKey, PackageFacts> = BTreeMap::new();
    let mut settings: BTreeMap<SettingId, Vec<Observed<SettingValue>>> = BTreeMap::new();
    let mut candidates: BTreeSet<CatalogId> = BTreeSet::new();
    let mut blind_spots = Vec::new();

    for fact in facts {
        sources.push(Observed::Seen(fact.source.backend.kind()));
        match &fact.claim {
            Claim::Setting { key, value } => {
                settings.entry(key.clone()).or_default().push(value.clone())
            }
            Claim::Unrecognized { candidates: c, .. } => candidates.extend(c.iter().cloned()),
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
            } => match &fact.subject {
                Subject::Service(instance) => {
                    states
                        .entry(instance.clone())
                        .or_default()
                        .push(state.clone());
                    services
                        .entry(instance.clone())
                        .or_default()
                        .push((*method, version.clone()));
                }
                other => blind_spots.extend(spot(
                    other,
                    Area::Services,
                    BlindSpotKind::WrongSubject,
                    "claim-on-wrong-subject",
                )),
            },
            Claim::Package {
                product,
                presence,
                version,
            } => match &fact.subject {
                Subject::Service(instance) => packages
                    .entry((instance.clone(), product.clone()))
                    .or_default()
                    .push((presence.clone(), version.clone())),
                other => blind_spots.extend(spot(
                    other,
                    Area::Packages,
                    BlindSpotKind::WrongSubject,
                    "claim-on-wrong-subject",
                )),
            },
            _ => {}
        }
    }

    let services = services
        .into_iter()
        .map(|(instance, found)| {
            let (value, notes) = fold_by_method(&found);
            for (what, hint) in notes {
                blind_spots.extend(spot(
                    &Subject::Service(instance.clone()),
                    Area::Services,
                    what,
                    hint,
                ));
            }
            (instance, value)
        })
        .collect();
    blind_spots.sort();
    blind_spots.dedup();

    SetupView {
        source: fold(&sources, |a, b| a == b),
        states: states
            .into_iter()
            .map(|(instance, found)| {
                let folded = fold(&found, |a, b| a == b);
                (
                    instance.clone(),
                    unless_candidate(folded, candidates.contains(&instance.catalog)),
                )
            })
            .collect(),
        settings: settings
            .into_iter()
            .map(|(key, found)| (key, fold(&found, |a, b| a == b)))
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
            .map(|(key, found)| {
                let folded = fold_package(&found);
                let maybe = candidates.contains(&key.1);
                (key, unless_candidate_package(folded, maybe))
            })
            .collect(),
    }
}

/// Something unrecognised might be this product, so its absence can't be
/// claimed: a not-found service becomes `Unknown(NotChecked)`.
fn unless_candidate(state: Observed<ServiceState>, maybe_it: bool) -> Observed<ServiceState> {
    match state {
        Observed::Seen(ServiceState::NotFound(_)) if maybe_it => not_checked(),
        other => other,
    }
}

/// The same for a package: not-installed becomes `Unknown(NotChecked)`.
fn unless_candidate_package(
    state: Observed<PackageState>,
    maybe_it: bool,
) -> Observed<PackageState> {
    match state {
        Observed::Seen(PackageState::NotInstalled) if maybe_it => not_checked(),
        other => other,
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

/// A service's version: only the best evidence counts.
///
/// - Among the `Seen` versions of the strongest method, they must agree, or the
///   answer is `Unknown(Conflict)`.
/// - A better method that reported `Conflict` is never replaced by a weaker
///   method's answer: the result is `Conflict`.
/// - A weaker method that saw a different version raises `MethodsDisagree`; a
///   better method that gave no answer at all raises `BetterMethodUnavailable`.
fn fold_by_method(
    found: &[(Method, Observed<PlainVersion>)],
) -> (Observed<PlainVersion>, Vec<(BlindSpotKind, &'static str)>) {
    let best_where = |pick: &dyn Fn(&Observed<PlainVersion>) -> bool| {
        found
            .iter()
            .filter(|(_, observed)| pick(observed))
            .map(|(method, _)| *method)
            .min()
    };
    let best_seen = best_where(&|o| matches!(o, Observed::Seen(_)));
    let best_conflict = best_where(&|o| {
        matches!(
            o,
            Observed::Unknown(Unknown {
                reason: UnknownReason::Conflict,
                ..
            })
        )
    });
    let best_gap =
        best_where(&|o| matches!(o, Observed::Unknown(u) if u.reason != UnknownReason::Conflict));

    let Some(best) = best_seen else {
        let reasons: Vec<UnknownReason> = found
            .iter()
            .filter_map(|(_, observed)| match observed {
                Observed::Unknown(unknown) => Some(unknown.reason),
                Observed::Seen(_) => None,
            })
            .collect();
        return (no_value(&reasons), Vec::new());
    };
    if best_conflict.is_some_and(|conflict| conflict <= best) {
        return (
            Observed::Unknown(Unknown::new(UnknownReason::Conflict)),
            Vec::new(),
        );
    }
    let top: Vec<Observed<PlainVersion>> = found
        .iter()
        .filter(|(method, _)| *method == best)
        .map(|(_, observed)| observed.clone())
        .collect();
    let winner = fold(&top, |a, b| a == b);
    let mut notes = Vec::new();
    if let Observed::Seen(chosen) = &winner
        && found.iter().any(|(method, observed)| {
            *method != best && matches!(observed, Observed::Seen(v) if v != chosen)
        })
    {
        notes.push((BlindSpotKind::MethodsDisagree, "methods-disagree"));
    }
    if best_gap.is_some_and(|gap| gap < best) {
        notes.push((
            BlindSpotKind::BetterMethodUnavailable,
            "better-method-unavailable",
        ));
    }
    (winner, notes)
}

/// A package from its presence and version observations. Presence is settled
/// first: present against absent is a conflict, and an absent package that
/// also carries a version contradicts itself. Only a package that is present
/// gets a version fold (which may still be unknown).
fn fold_package(found: &[(Observed<Presence>, Observed<PlainVersion>)]) -> Observed<PackageState> {
    let presences: Vec<Observed<Presence>> = found.iter().map(|(p, _)| p.clone()).collect();
    match fold(&presences, |a, b| a == b) {
        Observed::Unknown(unknown) => Observed::Unknown(Unknown::new(unknown.reason)),
        Observed::Seen(Presence::Absent(_)) => {
            if found
                .iter()
                .any(|(_, version)| matches!(version, Observed::Seen(_)))
            {
                Observed::Unknown(Unknown::new(UnknownReason::Conflict))
            } else {
                Observed::Seen(PackageState::NotInstalled)
            }
        }
        Observed::Seen(Presence::Present) => {
            let versions: Vec<Observed<PlainVersion>> =
                found.iter().map(|(_, v)| v.clone()).collect();
            Observed::Seen(PackageState::Installed(fold(&versions, |a, b| a == b)))
        }
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
