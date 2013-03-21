#ifndef _NETNODE_H
#define _NETNODE_H

#include <yaml-cpp\yaml.h>

#define uint unsigned int


using namespace std;

class NodeDescriptor
{
public:
	NodeDescriptor();
	NodeDescriptor(string desc, uint vulns);
private:
	string description;
	uint vulnVector;
};


#endif