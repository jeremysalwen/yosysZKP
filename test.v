module is28(input[7:0] X, output Y);

  assign Y = (X%4 ==0) && (X%7==0) && (X<40);
endmodule
