require 'cbc_padding_attack'
require 'openssl'

cipher     = OpenSSL::Cipher.new('aes-128-cbc')
key        = cipher.random_key
iv         = cipher.random_iv
plaintext  = ARGF.read || "Hello, glorious world!"
ciphertext = begin
  cipher.encrypt
  cipher.key = key
  cipher.iv  = iv
  cipher.update(plaintext) + cipher.final
end

oracle = ->(iv, ciphertext) do
  cipher.decrypt
  cipher.key = key
  cipher.iv  = iv
  (cipher.update(ciphertext) + cipher.final; true) rescue false
end

printer = ->(cpa, blocks, guess, padding, plaintext, block, bytes) do
  blocks  = [ iv ] + blocks
  length  = cpa.block_size * 2
  format  = "H#{length}"   * blocks.count
  guess   = blocks.dup.tap {|b| b[block] = guess }
  spacing = " " * (length * blocks.count.pred.pred + blocks.count.pred.pred)

  puts "Blocks   : " + blocks.join.unpack(format).join(' ')
  puts "Guess    : " + guess. join.unpack(format).join(' ')
  puts "Padding  : " + spacing + padding.    unpack(format).join(' ')
  puts "           " + spacing + '-' * length
  puts "Plaintext: " + spacing + plaintext.  unpack(format).join.rjust(length, "?")

  plaintext = plaintext.chars.map {|c| ('!'..'~').include?(c) ? c : ' ' }

  puts "           " + spacing + plaintext.join(' ').rjust(length, ' ').rstrip
  puts ""
end

cpa = CbcPaddingAttack.new('aes-128-cbc', iv, ciphertext, &oracle)

length = cpa.block_size * 2
format = "H#{length}" * cpa.block_count

puts "================================================"
puts "IV        : " + iv        .unpack(format).join
puts "Ciphertext: " + ciphertext.unpack(format).join(' ')
puts "================================================"
puts

puts cpa.plaintext(&printer)
