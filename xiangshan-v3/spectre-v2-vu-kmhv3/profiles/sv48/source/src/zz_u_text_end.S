.section .u_text,"ax",@progbits
.balign 4096
.globl __u_text_end
__u_text_end:
.section .a_data,"aw",@progbits
.balign 4096
.globl __a_data_end
__a_data_end:
.section .shared_data,"aw",@progbits
.balign 4096
.globl __shared_data_end
__shared_data_end:
.section .v_data,"aw",@progbits
.balign 4096
.globl __v_data_end
__v_data_end:
.previous
