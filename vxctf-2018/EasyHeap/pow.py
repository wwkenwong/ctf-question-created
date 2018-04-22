import angr
proj = angr.Project('./vxctf_heap', auto_load_libs=False)
#target=[0x000000000040160C]
#avoid=[0x000000000040138A,0x000000000040157E]
target=[0x00000000004017c6]
avoid=[0x00000000004017bc]
st = proj.factory.entry_state()

for _ in xrange(11):
    k = st.posix.files[0].read_from(1)
    st.se.add(k != 0)
    st.se.add(k != 10)
    st.se.add(k>=0x20)
    st.se.add(k<=0x7e)

st.posix.files[0].seek(0)
st.posix.files[0].length = 11


pg = proj.factory.path_group(st)
pg.explore(find=target,avoid=avoid)

print pg.found

print pg.found[0].posix.dumps(0)
