__u8 mapTypes[] = {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
};

__u8 MAPSIZE[] = {1, 2, 4, 8};

void createOneMap(union bpf_attr *mapAttr) {

    mapAttr->map_type = BPF_MAP_TYPE_ARRAY; //mapTypes[rand() % sizeof(mapTypes)];
    mapAttr->key_size = sizeof(int); // MAPSIZE[rand() % (sizeof(MAPSIZE))];
    mapAttr->value_size = sizeof(int); // MAPSIZE[rand() % (sizeof(MAPSIZE))];
    mapAttr->max_entries = 1024; // randNum32();
    // mapAttr->map_flags = BPF_F_NO_PREALLOC;

    /* bpf(BPF_MAP_CREATE, 
    {map_type=BPF_MAP_TYPE_ARRAY,
    key_size=4,
    value_size=48,
    max_entries=256,
    map_flags=0,
    inner_map_fd=0,
    map_name="bpf_map",
    map_ifindex=0,
    btf_fd=3,
    btf_key_type_id=0,
    btf_value_type_id=0,
    btf_vmlinux_value_type_id=0}, 72)

    bpf(BPF_MAP_CREATE, 
    {map_type=BPF_MAP_TYPE_ARRAY,
    key_size=4,
    value_size=4,
    max_entries=1024,
    map_flags=BPF_F_NO_PREALLOC,
    inner_map_fd=0,
    map_name="",
    map_ifindex=0,
    btf_fd=0,
    btf_key_type_id=0,
    btf_value_type_id=0}, 112)

    // TODO
    // mapAttr->map_flags = ... ;
    /*
        __u32   map_type;   // one of enum bpf_map_type
        __u32   key_size;   // size of key in bytes
        __u32   value_size; // size of value in bytes
        __u32   max_entries;    // max number of entries in a map
        __u32   map_flags;  // BPF_MAP_CREATE related flags defined above
        __u32   inner_map_fd;   // fd pointing to the inner map
        __u32   numa_node;  // numa node (effective only if BPF_F_NUMA_NODE is set).
        char    map_name[BPF_OBJ_NAME_LEN];
        __u32   map_ifindex;    // ifindex of netdev to create on
        __u32   btf_fd;     // fd pointing to a BTF type data
        __u32   btf_key_type_id;    // BTF type_id of the key
        __u32   btf_value_type_id;  // BTF type_id of the value
    };
    */
}