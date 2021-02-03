# frozen_string_literal: true

module Merkle
  class NodeBase
    attr_reader :encoding

    def child
      @child || (raise NoChildException)
    end

    def child=(child)
      @child = child
    end

    def left
      @left || (raise NoParentException)
    end

    def right
      @right || (raise NoParentException)
    end

    def left_parent?
      begin
        self == child.left
      rescue NoChildException
        false
      end
    end

    def right_parent?
      begin
        self == child.right
      rescue NoChildException
        false
      end
    end

    def parent?
      !!@child
    end

    def descendant(degree)
      if degree == 0
        self
      else
        raise NoDescendantException unless parent?
        child.descendant(degree - 1)
      end
    end

    private

    def initialize(encoding)
      @encoding = encoding
    end
  end

  class Leaf < NodeBase
    attr_reader :digest

    private

    def initialize(hashing, encoding, record = nil, digest = nil)
      if digest.nil? && record
        super(encoding)
        @digest = hashing.digest(record)
      elsif record.nil? && digest
        super(encoding)
        @digest = digest
      else
        raise LeafConstructionError.new('Either record or digest should be provided')
      end
    end
  end

  class Node < NodeBase
    attr_reader :digest

    def right=(right)
      @right = right
    end

    def recalculate_hash(hashing)
      @digest = hashing.digest(@left.digest, @right.digest)
    end

    private

    def initialize(hashing, encoding, left, right)
      super(encoding)
      @digest = hashing.digest(left.digest, right.digest)
      @left = left
      @right = right
      left.child = self
      right.child = self
    end
  end
end
