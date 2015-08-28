yosysZKP is a tool for performing Zero-Knowledge Proofs.

For information about Zero Knowledge proofs see 
https://en.wikipedia.org/wiki/Zero-knowledge_proof

yosysZKP uses a protocol which is very much like 
http://eprint.iacr.org/2014/934.pdf but which was independently derived 
from http://eprint.iacr.org/2013/073/20130220:185223

yosysZKP is meant to be practical in the sense that a non-expert should 
be able to use yosysZKP to prove non-trivial statements to a 
third-party.


The protocol:

1. PROVER and PROVEE agree on verilog circuit file.v containing module 
"module", and output file outputs.dat.  The protocol will prove to 
PROVEE that the circuit applied to PROVER's secret inputs will produce 
the agreed upon outputs. They should also agree on a level of security 
(128 bits should be enough).

The circuit file should be already synthesized, so it is composed entirely of 
low level gates.  In order to do this you can run  `yosys -o out.v -S in.v`

2. The PROVER creates the intitial secret and commitment
   $yosysZKP prover_create file.v module inputs.dat outputs.dat security_param out.secret out.comm

  The secret is kept private, and the commitment is sent to PROVEE.

3. The PROVEE records the commitment and responds to PROVER with a challenge
   $provee_respond in.comm provee.state out.resp

   The response is sent to PROVER

4. The PROVER responds to the challenge using his stored secret
   $prover_reveal in.secret in.resp out.reveal

   The reveal is sent to the PROVEE

5. The PROVEE verifies that the response is acceptable and the proof is valid
   $provee_validate file.v module outputs.dat security_param provee.state in.reveal
