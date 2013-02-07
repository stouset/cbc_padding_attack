require 'cbc_padding_attack/string/xor'
require 'openssl'

class CbcPaddingAttack
  attr_accessor :cipher
  attr_accessor :iv
  attr_accessor :ciphertext
  attr_accessor :oracle

  def initialize(cipher, iv, ciphertext, &oracle)
    self.cipher     = OpenSSL::Cipher.new(cipher)
    self.iv         = iv
    self.ciphertext = ciphertext
    self.oracle     = oracle
  end

  def block_size
    self.cipher.block_size
  end

  def block_count
    self.ciphertext.length / self.block_size
  end

  def blocks
    self.ciphertext.scan %r{.{#{self.block_size}}}
  end

  def plaintext(&printer)
    (self.block_count - 1).
      downto(0).
      map {|i| _crack_block(i, &printer) }.
      reverse.
      join
  end

  private

  def _crack_block(block, &printer)
    iv     = self.iv
    blocks = self.blocks[0..block]

    (self.block_size - 1).downto(0).inject("") do |plaintext, byte|
      padding   = _generate_padding(self.block_size - byte)
      guess     = _generate_guess(block, plaintext)
      plainbyte = _crack_byte(iv, blocks, guess, padding, block, byte)
      plaintext = plainbyte + plaintext

      printer[ self, blocks, guess, padding, plaintext, block, byte ] if printer

      plaintext
    end
  end

  def _generate_padding(length, value = length)
    (value.chr * length).rjust(self.block_size, 0.chr)
  end

  def _generate_guess(block, plaintext)
    length  = plaintext.length
    padding = _generate_padding(length, length + 1)
    chunks  = [ self.iv ] + self.blocks
    chunk   = chunks[block][(self.block_size - length)..-1]

    chunk     = chunk.    rjust(self.block_size, 0.chr)
    plaintext = plaintext.rjust(self.block_size, 0.chr)

    padding ^ plaintext ^ chunk
  end

  def _crack_byte(iv, blocks, guess, padding, block, byte)
    chunks        = [ self.iv ] + blocks
    chunks[block] = guess

    (2 ** 8).times.detect do |i|
      guess[byte]   = i.chr
      iv            = chunks.first
      ciphertext    = chunks.drop(1).join

      self.oracle[ iv, ciphertext ]
    end

    ( [ self.iv ] + blocks )[block][byte] ^
      guess  [byte] ^
      padding[byte]
  end
end
