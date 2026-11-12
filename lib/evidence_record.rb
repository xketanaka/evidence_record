# frozen_string_literal: true

require_relative "evidence_record/version"
require_relative "evidence_record/errors"
require_relative "evidence_record/digest"
require_relative "evidence_record/digest_algorithm"
require_relative "evidence_record/data"
require_relative "evidence_record/reduced_hashtree"
require_relative "evidence_record/hash_tree"
require_relative "evidence_record/der"
require_relative "evidence_record/algorithm_identifier"
require_relative "evidence_record/time_stamp_token"
require_relative "evidence_record/archive_time_stamp"
require_relative "evidence_record/chain"
require_relative "evidence_record/record"
require_relative "evidence_record/verifier"
require_relative "evidence_record/timestamp_validator"
require_relative "evidence_record/timestamp_exchange"
require_relative "evidence_record/generator"
require_relative "evidence_record/timestamp_renewal"

# Evidence Record Syntax (ERS), RFC 4998.
module EvidenceRecord
end
