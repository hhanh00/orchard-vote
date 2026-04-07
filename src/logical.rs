//! Halo2 chip implementing a zero-equality gate: given an advice cell `a`, produces
//! a new cell that is `1` if `a == 0` and `0` otherwise.
use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas::Base as Fp;

/// Column and selector assignments for the [`IsZeroChip`].
#[derive(Clone, Debug)]
pub struct IsZeroChipConfig {
    s: Selector,
    a: Column<Advice>,
    inv_a: Column<Advice>,
    is_zero: Column<Advice>,
}

/// Chip that constrains `is_zero = 1 - a * inv(a)`, implementing the is-zero check.
///
/// The gate enforces both `is_zero == 1 - a * inv_a` and `a * is_zero == 0`,
/// which together mean `is_zero` is `1` exactly when `a` is zero.
#[derive(Clone, Debug)]
pub struct IsZeroChip {
    config: IsZeroChipConfig,
}

impl Chip<Fp> for IsZeroChip {
    type Config = IsZeroChipConfig;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl IsZeroChip {
    /// Configures the is-zero gate within the given constraint system.
    ///
    /// `a` holds the input value, `inv_a` its modular inverse (or zero when `a` is zero),
    /// and `is_zero` the output boolean cell.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        a: Column<Advice>,
        inv_a: Column<Advice>,
        is_zero: Column<Advice>,
    ) -> IsZeroChipConfig {
        meta.enable_equality(a);
        meta.enable_equality(inv_a);
        meta.enable_equality(is_zero);
        let s = meta.selector();
        meta.create_gate("==0", |meta| {
            let s = meta.query_selector(s);
            let a = meta.query_advice(a.clone(), Rotation::cur());
            let inv_a = meta.query_advice(inv_a.clone(), Rotation::cur());
            let is_zero = meta.query_advice(is_zero, Rotation::cur());
            Constraints::with_selector(
                s,
                [
                    is_zero.clone() - (Expression::Constant(Fp::one()) - a.clone() * inv_a.clone()),
                    a * is_zero,
                ],
            )
        });

        IsZeroChipConfig {
            s,
            a,
            inv_a,
            is_zero,
        }
    }

    /// Constructs an [`IsZeroChip`] from a previously configured [`IsZeroChipConfig`].
    pub fn construct(config: IsZeroChipConfig) -> IsZeroChip {
        IsZeroChip { config }
    }

    /// Assigns a region that computes and constrains `is_zero = (a == 0) ? 1 : 0`.
    pub fn is_zero(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let config = &self.config;
        layouter.assign_region(
            || "is_zero",
            |mut region| {
                config.s.enable(&mut region, 0)?;
                let inv_a = a.value().map(|value| value.invert().unwrap_or(Fp::zero()));
                let is_zero = a.value().zip(inv_a).map(|(a, inv_a)| Fp::one() - a * inv_a);

                a.copy_advice(|| "a", &mut region, config.a, 0)?;
                region.assign_advice(|| "inv_a", config.inv_a, 0, || inv_a)?;
                let is_zero = region.assign_advice(|| "is_zero", config.is_zero, 0, || is_zero)?;
                Ok(is_zero)
            },
        )
    }
}
