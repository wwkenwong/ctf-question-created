 # vxctf 2018

## Ken Wong's sanity check

Brief writeup:

-Template return oriented programming question on x86-64 architecture

[solve.py](https://github.com/wwkenwong/ctf-question-created/blob/master/vxctf-2018/Ken%20Wong-s%20sanity%20check/solve.py)

## Christmas?

Why the question is call Christmas? Mainly is because of this paper [How the ELF Ruined Christmas](https://www.usenix.org/node/190923)

Brief writeup:

-The question has a buffer overflow

-Leak the remote libc with DynELF of pwntools 

-Do ROP and get shell

[solve.py](https://github.com/wwkenwong/ctf-question-created/blob/master/vxctf-2018/Christmas/solve.py)

## EasyHeap

Brief writeup:

-Use angr to solve the password of the login system

-Do fastbin attack with heap overflow vulnerabilities happens while edit the content

[solve.py](https://github.com/wwkenwong/ctf-question-created/blob/master/vxctf-2018/EasyHeap/solve.py)

## geeky server

Brief writeup:

-Use the UAF to leak the heap address

-Use the fmt bug to derandomization the PIE

-Do SROP with the syscall ret gadget by the BOF in the issue options

-Another way is by DynELF again ,and do ROP

[solve.py](https://github.com/wwkenwong/ctf-question-created/blob/master/vxctf-2018/geeky-server/solve.py)

## 64

Brief writeup

-Off by one caused by the inuse bit of the chunk

-Corrupt the size of next chunk

-Do fastbin attack with shirnk and extend the chunk, then hijack malloc hook 

-Fill it with the magic function

-(No one cares) In the original question, I did not included with "gift" and the magic, but envp suck while get shell with one gadget ,this two appears as a immediate fix to the question :( 

-Again the docker setup for this question got some issues, thx angelboy's advice, it would be improve in next contest (if any)

Again I apologize for any trouble caused due to the remote env issues

[solve.py](https://github.com/wwkenwong/ctf-question-created/blob/master/vxctf-2018/64/solve.py)

## Toxic K3n returns

-Set base on https://papers.nips.cc/paper/6802-hiding-images-in-plain-sight-deep-steganography

-Use online repo ->train a model ->recover the image-> with little guessing-> flag

-But all the team solve it with Photoshop (I should learn it before setting stego question :()

-Google Colab is a good place for playing AI stuff for free  https://medium.com/deep-learning-turkey/google-colab-free-gpu-tutorial-e113627b9f5d

-(Just ignore)(花了一段時問測試才找到一組可以在一個小時內train好的paramteter(readable),結果大家默默拿出photoshop就搞定,看來學好photoshop比tf 更重要 :()

[Toxic-K3n-returns](https://github.com/wwkenwong/ctf-question-created/tree/master/vxctf-2018/Toxic-K3n-returns)
