// Copyright 2024 The Erigon Authors
// This file is part of Erigon.
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/log/v3"
	"github.com/erigontech/erigon/cl/utils/bls"

	"github.com/erigontech/erigon/cl/abstract"
	"github.com/erigontech/erigon/cl/clparams"
	"github.com/erigontech/erigon/cl/cltypes"
	"github.com/erigontech/erigon/cl/cltypes/solid"
	"github.com/erigontech/erigon/cl/fork"
	"github.com/erigontech/erigon/cl/utils"
	"github.com/erigontech/erigon/cl/utils/threading"
)

const PreAllocatedRewardsAndPenalties = 8192

// these are view functions that should only getters, but are here as common utilities for packages to use

// GetEpochAtSlot gives the epoch for a certain slot
func GetEpochAtSlot(config *clparams.BeaconChainConfig, slot uint64) uint64 {
	return slot / config.SlotsPerEpoch
}

// Epoch returns current epoch.
func Epoch(b abstract.BeaconStateBasic) uint64 {
	return GetEpochAtSlot(b.BeaconConfig(), b.Slot())
}

func IsAggregator(cfg *clparams.BeaconChainConfig, committeeLength, committeeIndex uint64, slotSignature common.Bytes96) bool {
	modulo := max(1, committeeLength/cfg.TargetAggregatorsPerCommittee)
	hashSlotSignatue := utils.Sha256(slotSignature[:])
	return binary.LittleEndian.Uint64(hashSlotSignatue[:8])%modulo == 0
}

// GetTotalBalance return the sum of all balances within the given validator set.
func GetTotalBalance(b abstract.BeaconStateBasic, validatorSet []uint64) (uint64, error) {
	var (
		total uint64
	)
	for _, validatorIndex := range validatorSet {
		// Should be in bounds.
		delta, err := b.ValidatorEffectiveBalance(int(validatorIndex))
		if err != nil {
			return 0, err
		}
		total += delta
	}
	// Always minimum set to EffectiveBalanceIncrement
	if total < b.BeaconConfig().EffectiveBalanceIncrement {
		total = b.BeaconConfig().EffectiveBalanceIncrement
	}
	return total, nil
}

// GetTotalSlashingAmount return the sum of all slashings.
func GetTotalSlashingAmount(b abstract.BeaconState) (t uint64) {
	b.ForEachSlashingSegment(func(idx int, v uint64, total int) bool {
		t += v
		return true
	})
	return
}

// PreviousEpoch returns previous epoch.
func PreviousEpoch(b abstract.BeaconState) uint64 {
	epoch := Epoch(b)
	if epoch == 0 {
		return epoch
	}
	return epoch - 1
}

// GetBlockRoot returns blook root at start of a given epoch
func GetBlockRoot(b abstract.BeaconState, epoch uint64) (common.Hash, error) {
	return b.GetBlockRootAtSlot(epoch * b.BeaconConfig().SlotsPerEpoch)
}

// FinalityDelay determines by how many epochs we are late on finality.
func FinalityDelay(b abstract.BeaconState) uint64 {
	return PreviousEpoch(b) - b.FinalizedCheckpoint().Epoch
}

// InactivityLeaking returns whether epochs are in inactivity penalty.
// Implementation of is_in_inactivity_leak as defined in the ETH 2.0 specs.
func InactivityLeaking(b abstract.BeaconState) bool {
	return FinalityDelay(b) > b.BeaconConfig().MinEpochsToInactivityPenalty
}

// IsUnslashedParticipatingIndex
func IsUnslashedParticipatingIndex(validatorSet *solid.ValidatorSet, previousEpochParticipation *solid.ParticipationBitList, epoch, index uint64, flagIdx int) bool {
	validator := validatorSet.Get(int(index))
	return validator.Active(epoch) && cltypes.ParticipationFlags(previousEpochParticipation.Get(int(index))).HasFlag(flagIdx) && !validator.Slashed()
}

// EligibleValidatorsIndicies Implementation of get_eligible_validator_indices as defined in the eth 2.0 specs.
func EligibleValidatorsIndicies(b abstract.BeaconState) (eligibleValidators []uint64) {
	/* This is a parallel implementation of get_eligible_validator_indices*/

	// We divide computation into multiple threads to speed up the process.
	numThreads := runtime.NumCPU()
	wp := threading.NewParallelExecutor()
	eligibleValidatorsShards := make([][]uint64, numThreads)
	shardSize := b.ValidatorLength() / numThreads
	for i := range eligibleValidatorsShards {
		eligibleValidatorsShards[i] = make([]uint64, 0, shardSize)
	}
	previousEpoch := PreviousEpoch(b)
	// Iterate over all validators and include the active ones that have flag_index enabled and are not slashed.
	for i := 0; i < numThreads; i++ {
		workerID := i
		wp.AddWork(func() error {
			from := workerID * shardSize
			to := (workerID + 1) * shardSize
			if workerID == numThreads-1 {
				to = b.ValidatorLength()
			}
			for j := from; j < to; j++ {
				validator, err := b.ValidatorForValidatorIndex(j)
				if err != nil {
					panic(err)
				}
				if validator.Active(previousEpoch) || (validator.Slashed() && previousEpoch+1 < validator.WithdrawableEpoch()) {
					eligibleValidatorsShards[workerID] = append(eligibleValidatorsShards[workerID], uint64(j))
				}
			}
			return nil
		})
	}
	wp.Execute()
	// Merge the results from all threads.
	for i := range eligibleValidatorsShards {
		eligibleValidators = append(eligibleValidators, eligibleValidatorsShards[i]...)
	}

	return
}

func IsValidIndexedAttestation(b abstract.BeaconStateBasic, att *cltypes.IndexedAttestation) (bool, error) {
	inds := att.AttestingIndices
	if inds.Length() == 0 || !solid.IsUint64SortedSet(inds) {
		return false, errors.New("isValidIndexedAttestation: attesting indices are not sorted or are null")
	}

	pks := make([][]byte, 0, inds.Length())
	if err := solid.RangeErr[uint64](inds, func(_ int, v uint64, _ int) error {
		val, err := b.ValidatorForValidatorIndex(int(v))
		if err != nil {
			return err
		}
		pk := val.PublicKeyBytes()
		pks = append(pks, pk)
		return nil
	}); err != nil {
		return false, err
	}

	domain, err := b.GetDomain(b.BeaconConfig().DomainBeaconAttester, att.Data.Target.Epoch)
	if err != nil {
		return false, fmt.Errorf("unable to get the domain: %v", err)
	}

	signingRoot, err := fork.ComputeSigningRoot(att.Data, domain)
	if err != nil {
		return false, fmt.Errorf("unable to get signing root: %v", err)
	}

	valid, err := bls.VerifyAggregate(att.Signature[:], signingRoot[:], pks)
	if err != nil {
		return false, fmt.Errorf("error while validating signature: %v", err)
	}
	if !valid {
		return false, errors.New("invalid aggregate signature")
	}
	return true, nil
}

// GetUnslashedParticipatingIndices returns set of currently unslashed participating indexes.
func GetUnslashedParticipatingIndices(b abstract.BeaconState, flagIndex int, epoch uint64) (validatorSet []uint64, err error) {
	var participation *solid.ParticipationBitList
	// Must be either previous or current epoch
	switch epoch {
	case Epoch(b):
		participation = b.EpochParticipation(true)
	case PreviousEpoch(b):
		participation = b.EpochParticipation(false)
	default:
		return nil, errors.New("getUnslashedParticipatingIndices: only epoch and previous epoch can be used")
	}
	// Iterate over all validators and include the active ones that have flag_index enabled and are not slashed.
	b.ForEachValidator(func(validator solid.Validator, i, total int) bool {
		if !validator.Active(epoch) ||
			!cltypes.ParticipationFlags(participation.Get(i)).HasFlag(flagIndex) ||
			validator.Slashed() {
			return true
		}
		validatorSet = append(validatorSet, uint64(i))
		return true
	})
	return
}

// IsValidatorEligibleForActivationQueue returns whether the validator is eligible to be placed into the activation queue.
// Implementation of is_eligible_for_activation_queue.
// Specs at: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_eligible_for_activation_queue
// updated for Electra: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-is_eligible_for_activation_queue
func IsValidatorEligibleForActivationQueue(b abstract.BeaconState, validator solid.Validator) bool {
	if b.Version() <= clparams.DenebVersion {
		return validator.ActivationEligibilityEpoch() == b.BeaconConfig().FarFutureEpoch &&
			validator.EffectiveBalance() == b.BeaconConfig().MaxEffectiveBalance
	}
	// Electra and after
	return validator.ActivationEligibilityEpoch() == b.BeaconConfig().FarFutureEpoch &&
		validator.EffectiveBalance() >= b.BeaconConfig().MinActivationBalance
}

// IsValidatorEligibleForActivation returns whether the validator is eligible for activation.
// Implementation of is_eligible_for_activation.
// Specs at: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_eligible_for_activation
func IsValidatorEligibleForActivation(b abstract.BeaconState, validator solid.Validator) bool {
	return validator.ActivationEligibilityEpoch() <= b.FinalizedCheckpoint().Epoch &&
		validator.ActivationEpoch() == b.BeaconConfig().FarFutureEpoch
}

// IsMergeTransitionComplete returns whether a merge transition is complete by verifying the presence of a valid execution payload header.
func IsMergeTransitionComplete(b abstract.BeaconState) bool {
	if b.Version() < clparams.BellatrixVersion {
		return false
	}
	if b.Version() > clparams.BellatrixVersion {
		return true
	}
	return !b.LatestExecutionPayloadHeader().IsZero()
}

// ComputeTimestampAtSlot computes the Unix timestamp at the specified slot number.
func ComputeTimestampAtSlot(b abstract.BeaconState, slot uint64) uint64 {
	return b.GenesisTime() + (slot-b.BeaconConfig().GenesisSlot)*b.BeaconConfig().SecondsPerSlot
}

// ExpectedWithdrawals calculates the expected withdrawals that can be made by validators in the current epoch
func ExpectedWithdrawals(b abstract.BeaconState, currentEpoch uint64) ([]*cltypes.Withdrawal, uint64) {
	// Get the current epoch, the next withdrawal index, and the next withdrawal validator index
	nextWithdrawalIndex := b.NextWithdrawalIndex()
	nextWithdrawalValidatorIndex := b.NextWithdrawalValidatorIndex()

	// Determine the upper bound for the loop and initialize the withdrawals slice with a capacity of bound
	maxValidators := uint64(b.ValidatorLength())
	maxValidatorsPerWithdrawalsSweep := b.BeaconConfig().MaxValidatorsPerWithdrawalsSweep
	bound := min(maxValidators, maxValidatorsPerWithdrawalsSweep)
	withdrawals := make([]*cltypes.Withdrawal, 0, bound)
	partialWithdrawalsCount := uint64(0)

	// [New in Electra:EIP7251] Consume pending partial withdrawals
	cfg := b.BeaconConfig()
	if b.Version().AfterOrEqual(clparams.ElectraVersion) {
		b.GetPendingPartialWithdrawals().Range(func(index int, w *solid.PendingPartialWithdrawal, length int) bool {
			if w.WithdrawableEpoch > currentEpoch || len(withdrawals) == int(cfg.MaxPendingPartialsPerWithdrawalsSweep) {
				return false
			}
			validatorBalance, err := b.ValidatorBalance(int(w.Index))
			if err != nil {
				log.Warn("Failed to get validator balance", "index", w.Index, "error", err)
				return false
			}
			validator := b.ValidatorSet().Get(int(w.Index))
			if validator.ExitEpoch() == cfg.FarFutureEpoch &&
				validator.EffectiveBalance() >= cfg.MinActivationBalance &&
				validatorBalance > cfg.MinActivationBalance {
				wd := validator.WithdrawalCredentials()
				withdrawableBalance := min(validatorBalance-cfg.MinActivationBalance, w.Amount)
				withdrawals = append(withdrawals, &cltypes.Withdrawal{
					Index:     nextWithdrawalIndex,
					Validator: w.Index,
					Address:   common.BytesToAddress(wd[12:]),
					Amount:    withdrawableBalance,
				})
				nextWithdrawalIndex++
			}
			partialWithdrawalsCount++
			return true
		})
	}

	// Loop through the validators to calculate expected withdrawals
	for validatorCount := uint64(0); validatorCount < bound && len(withdrawals) != int(b.BeaconConfig().MaxWithdrawalsPerPayload); validatorCount++ {
		// Get the validator and balance for the current validator index
		// supposedly this operation is safe because we checked the validator length about
		currentValidator, _ := b.ValidatorForValidatorIndex(int(nextWithdrawalValidatorIndex))
		currentBalance, err := b.ValidatorBalance(int(nextWithdrawalValidatorIndex))
		if err != nil {
			log.Warn("Failed to get validator balance", "index", nextWithdrawalValidatorIndex, "error", err)
		}
		if b.Version() >= clparams.ElectraVersion {
			partiallyWithdrawnBalance := uint64(0)
			for _, w := range withdrawals {
				if w.Validator == nextWithdrawalValidatorIndex {
					partiallyWithdrawnBalance += w.Amount
				}
			}
			if currentBalance <= partiallyWithdrawnBalance {
				currentBalance = 0
			} else {
				currentBalance -= partiallyWithdrawnBalance
			}
		}
		wd := currentValidator.WithdrawalCredentials()
		// Check if the validator is fully withdrawable
		if isFullyWithdrawableValidator(b, currentValidator, currentBalance, currentEpoch) {
			// Add a new withdrawal with the validator's withdrawal credentials and balance
			newWithdrawal := &cltypes.Withdrawal{
				Index:     nextWithdrawalIndex,
				Validator: nextWithdrawalValidatorIndex,
				Address:   common.BytesToAddress(wd[12:]),
				Amount:    currentBalance,
			}
			withdrawals = append(withdrawals, newWithdrawal)
			nextWithdrawalIndex++
		} else if isPartiallyWithdrawableValidator(b, currentValidator, currentBalance) { // Check if the validator is partially withdrawable
			// Add a new withdrawal with the validator's withdrawal credentials and balance minus the maximum effective balance
			amount := currentBalance - b.BeaconConfig().MaxEffectiveBalance
			if b.Version() >= clparams.ElectraVersion {
				amount = currentBalance - getMaxEffectiveBalanceElectra(currentValidator, b.BeaconConfig())
			}
			newWithdrawal := &cltypes.Withdrawal{
				Index:     nextWithdrawalIndex,
				Validator: nextWithdrawalValidatorIndex,
				Address:   common.BytesToAddress(wd[12:]),
				Amount:    amount,
			}
			withdrawals = append(withdrawals, newWithdrawal)
			nextWithdrawalIndex++
		}
		// Increment the validator index, looping back to 0 if necessary
		nextWithdrawalValidatorIndex = (nextWithdrawalValidatorIndex + 1) % maxValidators
	}

	// Return the withdrawals slice
	return withdrawals, partialWithdrawalsCount
}
