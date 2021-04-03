# frozen_string_literal: true

require 'ffi'

module PuTTY
  module Key
    # A wrapper for the required functions from libargon2.
    module Libargon2
      extend ::FFI::Library

      ffi_lib ['argon2', 'libargon2.so.1', 'libargon2.dll', 'Argon2OptDll.dll', 'Argon2RefDll.dll']

      # Returned by `argon2_hash` if successful.
      ARGON2_OK = 0

      # The type of hash to perform.
      enum :argon2_type, [:d, 0, :i, 1, :id, 2]

      # The version of the algorithm to use.
      enum FFI::Type::UINT32, :argon2_version, [:version_10, 0x10, :version_13, 0x13]

      # Hashes a password with Argon2, producing a raw hash at hash.
      #
      #   t_cost Number of iterations.
      #   m_cost Sets memory usage to m_cost kibibytes.
      #   parallelism Number of threads and compute lanes.
      #   pwd Pointer to password.
      #   pwdlen Password size in bytes.
      #   salt Pointer to salt.
      #   saltlen Salt size in bytes.
      #   hash Buffer where to write the raw hash - updated by the function.
      #   hashlen Desired length of the hash in bytes.
      #
      # Different parallelism levels will give different results.
      #
      # Returns ARGON2_OK if successful.
      #
      # ARGON2_PUBLIC int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
      #                               const uint32_t parallelism, const void *pwd,
      #                               const size_t pwdlen, const void *salt,
      #                               const size_t saltlen, void *hash,
      #                               const size_t hashlen, char *encoded,
      #                               const size_t encodedlen, argon2_type type,
      #                               const uint32_t version);
      attach_function 'argon2_hash', [:uint32, :uint32, :uint32, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :pointer, :size_t, :argon2_type, :argon2_version], :int

      # Returns an error message corresponding to the given error code.
      #
      # ARGON2_PUBLIC const char *argon2_error_message(int error_code);
      attach_function :argon2_error_message, [:int], :string
    end
    private_constant :Libargon2
  end
end
