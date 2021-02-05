# frozen_string_literal: true

require 'digest'
require 'set'

module Merkle
  class Tree
    attr_reader :hashing, :leaves, :nodes

    def empty?
      @nodes.empty?
    end

    def root
      raise EmptyTreeException if empty?
      @root
    end

    def root_hash
      raise EmptyTreeException if empty?
      @root.digest
    end

    def commitment
      begin
        root_hash
      rescue EmptyTreeException
        nil
      end
    end

    def length
      @leaves.length
    end

    def size
      @nodes.length
    end

    def height
      # Since the tree is binary *balanced*, its height coincides
      # with the length of its leftmost branch
      len = @leaves.length
      len == 0 ? 0 : Math.log2(len).ceil
    end

    def encoding
      @hashing.encoding
    end

    def security
      @hashing.security
    end

    def update(record: nil, digest: nil)
      new_leaf = Leaf.new(@hashing, encoding, record, digest)
      if empty?
        @leaves << new_leaf
        @nodes << new_leaf
        @root = new_leaf
      else
        # ~ Height and root of the *full* binary subtree with maximum
        # ~ possible length containing the rightmost leaf
        len = @leaves.length
        least_significant_one = Math.log2(len & -len).to_i
        last_subroot = @leaves[-1].descendant(least_significant_one)

        @leaves << new_leaf
        @nodes << new_leaf

        if last_subroot.parent?
          old_child = last_subroot.child

          # Create bifurcation node
          new_node = Node.new(@hashing, encoding, last_subroot, new_leaf)
          @nodes << new_node

          # Interject bifurcation node
          old_child.right = new_node
          new_node.child = old_child

          # Recalculate hashes only at the rightmost branch of the tree
          current_node = old_child
          loop do
            current_node.recalculate_hash(@hashing)
            break unless current_node.parent?
            current_node = current_node.child
          end
        else
          new_node = Node.new(@hashing, encoding, last_subroot, new_leaf)
          @nodes << new_node
          @root = new_node
        end
      end
    end

    # Detects the (zero-based) index of the leftmost leaf which stores the provided checksum
    def index(checksum)
      @leaves.index { |leaf| leaf.digest == checksum }
    end

    # Low-level audit proof
    def audit_path(index)
      raise NoPathException if index.nil? || index < 0

      unless current_node = @leaves[index]
        raise NoPathException
      end

      path = [[current_node.right_parent? ? -1 : 1, current_node.digest]]
      start = 0
      loop do
        break unless current_node.parent?
        current_child = current_node.child

        if current_node.left_parent?
          next_digest = current_child.right.digest
          path.append([current_child.left_parent? ? +1 : -1, next_digest])
        else
          next_digest = current_child.left.digest
          path.prepend([current_child.right_parent? ? -1 : +1, next_digest])
          start += 1
        end

        current_node = current_child
      end

      [start, path]
    end

    def audit_proof(checksum, commit: false)
      index = index(checksum)
      commitment = commit ? self.commitment : nil
      proof_index, audit_path =
        begin
          audit_path(index)
        rescue NoPathException
          [-1, []]
        end

      Proof.new(
        algorithm: @hashing.algorithm,
        encoding: @hashing.encoding,
        security: @hashing.security,
        commitment: commitment,
        proof_index: proof_index,
        proof_path: audit_path
      )
    end

    def consistency_proof(subhash, commit: false)
      raise 'hello'
    end

    def merkle_proof(challenge, commit: true)
      if challenge.audit?
        audit_proof(challenge.checksum, commit: commit)
      else
        consistency_proof(challenge.subhash, commit: commit)
      end
    end

    def clear
      @leaves = []
      @nodes = Set[]
      @root = nil
    end

    def pp
      <<~STR
      hash-type : #{@hashing.algorithm}
      encoding  : #{encoding}
      security  : #{security ? 'ACTIVATED' : 'DEACTIVATED'}

      root-hash : #{empty? ? '[None]' : root_hash}

      length    : #{length}
      size      : #{size}
      height    : #{height}
      STR
    end

    def pt(indent: 3)
      empty? ? "\u2514\u2500[None]\n" : root.pt(indent: indent)
    end

    private

    def initialize(*records, algorithm: Digest::SHA256, encoding: 'utf-8', security: true)
      # Hashing configuration
      @hashing = Hashing.new(algorithm: algorithm, encoding: encoding, security: security)

      # Tree generation
      @leaves = []
      @nodes = Set[]
      records.each { |record| update(record: record) }
    end
  end
end
