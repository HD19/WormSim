#ifndef _NETMAP_H
#define _NETMAP_H

#include "Common.h"
#include "Node.h"

using namespace std;

class NetworkMap
{
public:
	//Not sure yet
	NetworkMap();

private:
	uint numNodes;
	string description;
	string address;
	Graph netGraph;
	vector<NodeDescriptor*>; //Defines all the different node types.

};

#endif
