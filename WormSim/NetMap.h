#ifndef _NETMAP_H
#define _NETMAP_H

#include <iostream>
#include <string>
#include <fstream>
#include "NetNode.h"


#define NET_CONFIG_PATH "network.yml"


using namespace std;

class NetworkMap
{
public:
	NetworkMap();
	NetworkMap(MyRNG* randomGen);
	void setRNG(MyRNG* randomGen);
private:
	bool readConfiguration();
	bool generateGraph();
	IPAddress* getIPBlock(string& inAddr, unsigned int maskBits);
	IPAddress* getIPBlock(unsigned int maskBits);
	MyRNG* theRNG;
	uint numNodes;
	Graph netGraph;
	vector<IPAddress*> allocatedIPs;
	map<string, Vulnerability*> vulnMap;
	map<string, NodeType*> nodeTypeMap;
	map<string, Gateway*> gatewayMap;
	map<string, Graph::vertex_descriptor> vertexMap;
	vector<RouteEntry*> routeList;

};

#endif
