#ifndef _NETNODE_H
#define _NETNODE_H

#include <yaml-cpp\yaml.h>

#include <boost\graph\undirected_graph.hpp>
#include <map>
#include <random>

#include "Util.h"

#define uint unsigned int

using namespace std;



typedef boost::undirected_graph<> Graph;
typedef std::mt19937 MyRNG;

//Defines how the graph is distributed across different types in the gateway subgraph
enum class GraphDist { Random, Count/*, Range, Manual*/ };

//Defines different states the node can be in
enum class NodeStatus{ Clean, Infected, Disabled };

class Vulnerability
{
public:
	Vulnerability();
	Vulnerability(string identifier, string description);
	void operator << (const YAML::Node& node);
	const string& getID();
	const string& getDesc();
private:
	string vulnID;
	string desc;
};

typedef vector<Vulnerability*> VulnVect;
typedef vector<Vulnerability*>::iterator VulnVectIter;

class NodeType
{
public:
	NodeType();
	NodeType(string ID, string desc);
	void operator << (const YAML::Node& node);
	VulnVect& getVulnVector();
	string& getID();
	string& getDesc();
	bool addVuln(Vulnerability* toAdd);
	bool removeVuln(Vulnerability* toRem);
	void addVulns(VulnVect& toAdd);
	void removeVulns(VulnVect& toRem);
private:
	string nodeID;
	string desc;
	VulnVect vulnVector;
	vector<string> vulnsToAdd; //Can't store references as they might be destroyed when the YAML::Node disappears.
};

typedef vector<NodeType*> NTVect;
typedef vector<NodeType*>::iterator NTVectIter;

struct NodeInstance
{
	uint nAddr;
	NodeStatus nStatus;
	NodeType* nType;
};

typedef map<uint, NodeInstance> GatewayMap;

class Gateway
{
	friend class NetworkMap;
public:
	Gateway();
	Gateway(string ID, string desc);	//Assume maskbits is 24
	Gateway(string ID, unsigned char maskBits, string desc);
	void operator << (const YAML::Node& node);
protected:
	void setRNG(MyRNG* ref);
	bool generateSubGraph(vector<NodeInstance*>* target); // Will generate a graph based on the given configuration and distribution.
	bool generateSubGraph(map<string, int>& nodeMap, vector<NodeInstance*>* target);
	NTVect nodeTypes;
	vector<string> nodeTypesToAdd;
private:
	//bool generateSubGraph(map<string, vector<string>>& nodeMap); This is if we had the manual method defined.
	GraphDist subGraphDist;
	string gateID;
	string desc;
	uint maskBits; //Needs to be checked by creator against assigned address.
	uint nodeCount;
	MyRNG* theRng;
	//IPAddress should be defined as an actual graph description, here we're only defining the TYPE
	//string ipAddr; //String representation of IP, could be a range or what have you, need to build a utility for dealing with this	

};

typedef struct routeEntry
{
	string name;
	string address;
	Gateway* gateType;
	vector<struct routeEntry*> edges;
} RouteEntry;
#endif