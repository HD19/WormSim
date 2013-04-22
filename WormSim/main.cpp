#include "Common.h"
#include "NetMap.h"


using namespace std;


int main(int argc, char* argv[])
{
	MyRNG rng;

	rng.seed(time(0));

	NetworkMap mainNetMap(&rng);

	

	cout << "Done!" << endl;
	return EXIT_SUCCESS;
}