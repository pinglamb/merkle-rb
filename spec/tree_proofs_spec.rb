# frozen_string_literal: true

RSpec.describe Merkle::Tree do
  describe '#merkle_proof' do
    context 'for audit proof' do
      before :each do
        @tree = Merkle::Tree.new(*(0...666).collect { |i| "#{i}-th record" })
      end

      it 'works for item in tree' do
        challenge = Merkle::Challenge.new(checksum: @tree.hashing.digest('100-th record'))
        proof = @tree.merkle_proof(challenge)
        expected_proof = @tree.audit_proof(challenge.checksum)
        expect(proof.commitment).to eq(@tree.root_hash)
        expect(proof.proof_index).to eq(expected_proof.proof_index)
        expect(proof.proof_path).to eq(expected_proof.proof_path)
      end

      it 'works for item not in tree' do
        challenge = Merkle::Challenge.new(checksum: @tree.hashing.digest('anything non recorded...'))
        proof = @tree.merkle_proof(challenge)
        expected_proof = @tree.audit_proof(challenge.checksum)
        expect(proof.commitment).to eq(@tree.root_hash)
        expect(proof.proof_index).to eq(expected_proof.proof_index)
        expect(proof.proof_path).to eq(expected_proof.proof_path)
      end
    end
  end

  tree0 = Merkle::Tree.new
  tree1 = Merkle::Tree.new(*%w[a])
  tree2 = Merkle::Tree.new(*%w[a b])
  tree3 = Merkle::Tree.new(*%w[a b c])
  tree4 = Merkle::Tree.new(*%w[a b c d])
  tree5 = Merkle::Tree.new(*%w[a b c d e])

  describe '#audit_path' do
    [
      [tree0, 0],
      [tree1, nil],
      [tree1, 1],
      [tree2, nil],
      [tree2, 2],
      [tree3, nil],
      [tree3, 3],
      [tree4, nil],
      [tree4, 4],
      [tree5, nil],
      [tree5, 5]
    ].each do |(tree, index)|
      it "raises NoPathException for (tree-length: #{tree.length}, index: #{index || 'nil'})" do
        expect { tree.audit_path(index) }.to raise_error(Merkle::NoPathException)
      end
    end

    [
      [tree1, 0, [0, [[+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']]]],
      [
        tree2,
        0,
        [
          0,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [-1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31']
          ]
        ]
      ],
      [
        tree2,
        1,
        [
          1,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [-1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31']
          ]
        ]
      ],
      [
        tree3,
        0,
        [
          0,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [
        tree3,
        1,
        [
          1,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [-1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [
        tree3,
        2,
        [
          1,
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [
        tree4,
        0,
        [
          0,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [-1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138']
          ]
        ]
      ],
      [
        tree4,
        1,
        [
          1,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [-1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [-1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138']
          ]
        ]
      ],
      [
        tree4,
        2,
        [
          1,
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'],
            [-1, 'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d']
          ]
        ]
      ],
      [
        tree4,
        3,
        [
          2,
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'],
            [-1, 'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d']
          ]
        ]
      ],
      [
        tree5,
        0,
        [
          0,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [+1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        1,
        [
          1,
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [-1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [+1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        2,
        [
          1,
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'],
            [-1, 'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        3,
        [
          2,
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'],
            [-1, 'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        4,
        [
          1,
          [
            [+1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ]
    ].each do |tree, index, expected|
      it "works for (length: #{tree.length}, index: #{index || 'nil'})" do
        expect(tree.audit_path(index)).to eq(expected)
      end
    end
  end

  describe '#subroot' do
    [
      [tree0, 0, 'anything'],
      [tree1, 1, 'anything'],
      [tree2, 2, 'anything'],
      [tree2, 0, 2],
      [tree2, 1, 1],
      [tree3, 3, 'anything'],
      [tree3, 0, 3],
      [tree3, 1, 1],
      [tree3, 2, 1],
      [tree4, 4, 'anything'],
      [tree4, 0, 3],
      [tree4, 1, 1],
      [tree4, 2, 2],
      [tree4, 3, 1],
      [tree5, 5, 'anything'],
      [tree5, 0, 3],
      [tree5, 0, 4],
      [tree5, 1, 1],
      [tree5, 2, 2],
      [tree5, 3, 1],
      [tree5, 4, 1]
    ].each do |tree, start, height|
      it "raises NoSubtreeException (length: #{tree.length}, start: #{start}, height: #{height})" do
        expect { tree.subroot(start, height) }.to raise_error(Merkle::NoSubtreeException)
      end
    end

    [
      [tree1, 0, 0, tree1.leaves[0]],
      [tree2, 0, 0, tree2.leaves[0]],
      [tree2, 0, 1, tree2.root],
      [tree2, 1, 0, tree2.leaves[1]],
      [tree3, 0, 0, tree3.leaves[0]],
      [tree3, 0, 1, tree3.leaves[0].child],
      [tree3, 1, 0, tree3.leaves[1]],
      [tree3, 2, 0, tree3.leaves[2]],
      [tree4, 0, 0, tree4.leaves[0]],
      [tree4, 0, 1, tree4.leaves[0].child],
      [tree4, 0, 2, tree4.root],
      [tree4, 1, 0, tree4.leaves[1]],
      [tree4, 2, 0, tree4.leaves[2]],
      [tree4, 2, 1, tree4.leaves[2].child],
      [tree4, 3, 0, tree4.leaves[3]],
      [tree5, 0, 0, tree5.leaves[0]],
      [tree5, 0, 1, tree5.leaves[0].child],
      [tree5, 0, 2, tree5.leaves[0].child.child],
      [tree5, 1, 0, tree5.leaves[1]],
      [tree5, 2, 0, tree5.leaves[2]],
      [tree5, 2, 1, tree5.leaves[2].child],
      [tree5, 3, 0, tree5.leaves[3]],
      [tree5, 4, 0, tree5.leaves[4]]
    ].each do |tree, start, height, expected|
      it "works (length: #{tree.length}, start: #{start}, height: #{height})" do
        expect(tree.subroot(start, height)).to eq(expected)
      end
    end
  end

  describe '#principal_subroots' do
    [
      [tree1, -1],
      [tree1, +2],
      [tree2, -1],
      [tree2, +3],
      [tree3, -1],
      [tree3, +4],
      [tree4, -1],
      [tree4, +5],
      [tree5, -1],
      [tree5, +6]
    ].each do |tree, sublength|
      it "raises NoPrincipalSubroots (length: #{tree.length}, sublength: #{sublength})" do
        expect { tree.principal_subroots(sublength) }.to raise_error(Merkle::NoPrincipalSubroots)
      end
    end

    [
      [tree0, 0, []],
      [tree1, 0, []],
      [tree1, 1, [[+1, tree1.root]]],
      [tree2, 0, []],
      [tree2, 1, [[+1, tree2.leaves[0]]]],
      [tree2, 2, [[+1, tree2.root]]],
      [tree3, 0, []],
      [tree3, 1, [[+1, tree3.leaves[0]]]],
      [tree3, 2, [[+1, tree3.leaves[0].child]]],
      [tree3, 3, [[+1, tree3.leaves[0].child], [+1, tree3.leaves[2]]]],
      [tree4, 0, []],
      [tree4, 1, [[+1, tree4.leaves[0]]]],
      [tree4, 2, [[+1, tree4.leaves[0].child]]],
      [tree4, 3, [[+1, tree4.leaves[0].child], [+1, tree4.leaves[2]]]],
      [tree4, 4, [[+1, tree4.root]]],
      [tree5, 0, []],
      [tree5, 1, [[+1, tree5.leaves[0]]]],
      [tree5, 2, [[+1, tree5.leaves[0].child]]],
      [tree5, 3, [[+1, tree5.leaves[0].child], [+1, tree5.leaves[2]]]],
      [tree5, 4, [[+1, tree5.leaves[0].child.child]]],
      [tree5, 5, [[+1, tree5.leaves[0].child.child], [+1, tree5.leaves[-1]]]]
    ].each do |tree, sublength, expected|
      it "works (length: #{tree.length}, sublength: #{sublength})" do
        expect(tree.principal_subroots(sublength)).to eq(expected)
      end
    end
  end

  describe '#minimal_complement' do
    [
      [tree0, [], []],
      [tree1, [], [[+1, tree1.leaves[0]]]],
      [tree1, [[+1, tree1.root]], []],
      [tree2, [], [[+1, tree2.root]]],
      [tree2, [[+1, tree2.leaves[0]]], [[+1, tree2.leaves[1]]]],
      [tree2, [[+1, tree2.root]], []],
      [tree3, [], [[+1, tree3.leaves[0].child], [+1, tree3.leaves[2]]]],
      [tree3, [[+1, tree3.leaves[0]]], [[+1, tree3.leaves[1]], [+1, tree3.leaves[2]]]],
      [tree3, [[+1, tree3.leaves[0].child]], [[+1, tree3.leaves[2]]]],
      [tree3, [[+1, tree3.leaves[0].child], [+1, tree3.leaves[2]]], []],
      [tree4, [], [[+1, tree4.root]]],
      [tree4, [[+1, tree4.leaves[0]]], [[+1, tree4.leaves[1]], [+1, tree4.leaves[2].child]]],
      [tree4, [[+1, tree4.leaves[0].child]], [[+1, tree4.leaves[2].child]]],
      [tree4, [[+1, tree4.leaves[0].child], [+1, tree4.leaves[2]]], [[-1, tree4.leaves[3]]]],
      [tree4, [[+1, tree4.root]], []],
      [tree5, [], [[+1, tree5.leaves[0].child.child], [+1, tree5.leaves[4]]]],
      [tree5, [[+1, tree5.leaves[0]]], [[+1, tree5.leaves[1]], [+1, tree5.leaves[2].child], [+1, tree5.leaves[4]]]],
      [tree5, [[+1, tree5.leaves[0].child]], [[+1, tree5.leaves[2].child], [+1, tree5.leaves[4]]]],
      [tree5, [[+1, tree5.leaves[0].child], [+1, tree5.leaves[2]]], [[-1, tree5.leaves[3]], [+1, tree5.leaves[4]]]],
      [tree5, [[+1, tree5.leaves[0].child.child]], [[+1, tree5.leaves[4]]]],
      [tree5, [[+1, tree5.leaves[0].child.child], [+1, tree5.leaves[4]]], []]
    ].each do |tree, subroots, expected|
      it "works (length: #{tree.length}, subroots: #{subroots.size})" do
        expect(tree.minimal_complement(subroots)).to eq(expected)
      end
    end
  end

  describe '#consistency_path' do
    [
      [tree0, -1],
      [tree0, +0],
      [tree0, +1],
      [tree1, -1],
      [tree1, +2],
      [tree2, -1],
      [tree2, +3],
      [tree3, -1],
      [tree3, +4],
      [tree4, -1],
      [tree4, +5],
      [tree5, -1],
      [tree5, +6]
    ].each do |tree, sublength|
      it "raises NoPathException (length: #{tree.length}, sublength: #{sublength})" do
        expect { tree.consistency_path(sublength) }.to raise_error(Merkle::NoPathException)
      end
    end

    [
      [tree1, 0, [+0, [], [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']]]],
      [
        tree1,
        1,
        [
          +0,
          [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']],
          [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']]
        ]
      ],
      [tree2, 0, [+0, [], [[-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20']]]],
      [
        tree2,
        1,
        [
          +0,
          [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']],
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31']
          ]
        ]
      ],
      [
        tree2,
        2,
        [
          +0,
          [[-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20']],
          [[-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20']]
        ]
      ],
      [
        tree3,
        0,
        [
          +1,
          [],
          [
            [-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [
        tree3,
        1,
        [
          +0,
          [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']],
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [+1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [
        tree3,
        2,
        [
          +0,
          [[-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20']],
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [
        tree3,
        3,
        [
          +1,
          [
            [-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ],
          [
            [-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ]
        ]
      ],
      [tree4, 0, [+0, [], [[-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417']]]],
      [
        tree4,
        1,
        [
          +0,
          [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']],
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [+1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138']
          ]
        ]
      ],
      [
        tree4,
        2,
        [
          +0,
          [[-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20']],
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138']
          ]
        ]
      ],
      [
        tree4,
        3,
        [
          +1,
          [
            [-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ],
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'],
            [-1, 'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d']
          ]
        ]
      ],
      [
        tree4,
        4,
        [
          +0,
          [[-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417']],
          [[-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417']]
        ]
      ],
      [
        tree5,
        0,
        [
          +1,
          [],
          [
            [-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        1,
        [
          +0,
          [[-1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c']],
          [
            [+1, '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'],
            [+1, '57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'],
            [+1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'],
            [+1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        2,
        [
          +0,
          [[-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20']],
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, 'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'],
            [+1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        3,
        [
          +1,
          [
            [-1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [-1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8']
          ],
          [
            [+1, '9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'],
            [+1, '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'],
            [-1, 'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'],
            [+1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        4,
        [
          +0,
          [[-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417']],
          [
            [+1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'],
            [+1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ],
      [
        tree5,
        5,
        [
          +1,
          [
            [-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ],
          [
            [-1, '22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'],
            [-1, '2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4']
          ]
        ]
      ]
    ].each do |tree, sublength, expected|
      it "works (length: #{tree.length}, sublength: #{sublength})" do
        expect(tree.consistency_path(sublength)).to eq(expected)
      end
    end
  end
end
