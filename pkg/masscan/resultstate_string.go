// Code generated by "stringer -type=ResultState"; DO NOT EDIT.

package masscan

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ResultState_UNKNOWN-0]
	_ = x[ResultState_OPEN-1]
	_ = x[ResultState_CLOSE-2]
}

const _ResultState_name = "ResultState_UNKNOWNResultState_OPENResultState_CLOSE"

var _ResultState_index = [...]uint8{0, 19, 35, 52}

func (i ResultState) String() string {
	if i < 0 || i >= ResultState(len(_ResultState_index)-1) {
		return "ResultState(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _ResultState_name[_ResultState_index[i]:_ResultState_index[i+1]]
}