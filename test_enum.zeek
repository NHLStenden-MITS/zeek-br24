type interference_rejection_enum : enum{
		interference_rejection_OFF = 0,
		interference_rejection_LOW = 1,
		interference_rejection_MEDIUM = 2,
		interference_rejection_HIGH = 3
	};

const interference_rejection_map: table[int] of interference_rejection_enum = {
    [0] = interference_rejection_OFF,
    [1] = interference_rejection_LOW,
    [2] = interference_rejection_MEDIUM,
    [3] = interference_rejection_HIGH
};


local data: string = "\x00";
local data_val: count = bytestring_to_count(data, T);

if ( data_val in interference_rejection_map ) {
    local value: interference_rejection_enum = interference_rejection_map[data_val];
    print "value", value;
}

# local value: interference_rejection_enum = interference_rejection_enum(data_val);

# assert 1 == cast<uint64>(b);

# print "data_val", data_val;


# type Status: enum {
#     OK = 0,
#     ERROR = 1,
#     UNKNOWN = 2
# };

# # Create a mapping manually
# global int_to_status: table[int] of Status = {
#     [0] = OK,
#     [1] = ERROR,
#     [2] = UNKNOWN
# };


# local i = 1;
# if (i in int_to_status) {
#     local status_val = int_to_status[i];
#     print fmt("Converted %d to enum: %s", i, status_val);
# } else {
#     print fmt("Invalid index: %d", i);
# }

