#include "NetNode.h"

Vulnerability::Vulnerability()
{

}

Vulnerability::Vulnerability(string identifier, string description): vulnID(identifier), desc(description)
{

}

const string& Vulnerability::getID()
{
	return this->vulnID;
}

const string& Vulnerability::getDesc()
{
	return this->desc;
}

void Vulnerability::operator << (const YAML::Node& node)
{
	try
	{
		node["ID"] >> this->vulnID;
		node["Desc"] >> this->desc;
	}
	catch(exception& ex)
	{
		cout << "[-] Failed to read Vulnerability node:" << endl << ex.what() << endl;
		return;
	}
}

NodeType::NodeType()
{
	return;
}

NodeType::NodeType(string ID, string desc): nodeID(ID), desc(desc)
{
	return;
}

void NodeType::operator<<(const YAML::Node& node)
{
	//Look at the spec and fill in the appropriate variables
	try
	{
		node["ID"] >> this->nodeID;
		node["Desc"] >> this->desc;

		const YAML::Node& tmpNode = node["Vulns"];
		for(YAML::Iterator it = tmpNode.begin(); it != tmpNode.end(); it++)
		{
			//Add each vulnerability ID to the vector of vulns we need to link and resolve later.
			string tmpStrCopy;
			(*it) >> tmpStrCopy;
			this->vulnsToAdd.push_back(tmpStrCopy);
		}
	}
	catch (exception& ex)
	{
		cout << "[-] Failed to NodeType node: " << ex.what() << endl;
		return;
	}
}

VulnVect& NodeType::getVulnVector()
{
	return this->vulnVector;
}

string& NodeType::getID()
{
	return this->nodeID;
}

string& NodeType::getDesc()
{
	return this->desc;
}

bool NodeType::addVuln(Vulnerability* toAdd)
{
	try
	{
		this->vulnVector.push_back(toAdd);
	}
	catch (exception& ex)
	{
		cout << "[-] Failed to add vuln to NodeType vuln vector: " << ex.what() << endl;
		return false;
	}
	return true;
}

bool NodeType::removeVuln(Vulnerability* toRem)
{
	try
	{
		for(VulnVectIter it = vulnVector.begin(); it != vulnVector.end(); it++)
		{
			Vulnerability* tmpVuln = (*it);
			if(tmpVuln->getID() == toRem->getID())
			{
				vulnVector.erase(it);
			}
			return true;
		}
		cout << "[-] Failed to remove vuln (" << toRem->getID() << ") from NodeType (" << this->getID() << ") as it doesn't exist in this NodeType" << endl;
		return false;
	}
	catch( exception& ex)
	{
		cout << "[-] Failed to remove vuln (" << toRem->getID() << ") from NodeType (" << this->getID() << ") " << ex.what() << endl;
		return false;
	}
}

void NodeType::addVulns(VulnVect& toAdd)
{
	cout << "[+] Adding " << toAdd.size() << " vulns to " << this->nodeID << " nodeType" << endl;
	uint okAdd = 0;

	for(uint i = 0; i < toAdd.size(); i++)
	{
		if(this->addVuln(toAdd[i]))
		{
			okAdd++;
		}
	}

	cout << " [+] Added " << okAdd << " of " << toAdd.size() << endl;
	return;
}

void NodeType::removeVulns(VulnVect& toRem)
{
	cout << "[+] Removing " << toRem.size() << " vulns from " << this->nodeID << " nodeType" << endl;
	uint okRem = 0;

	for(uint i = 0; i < toRem.size(); i++)
	{
		if(this->removeVuln(toRem[i]))
		{
			okRem++;
		}
	}

	cout << " [+] Removed " << okRem << " of " << toRem.size() << endl;
	return;
}

Gateway::Gateway()
{
	return;
}

Gateway::Gateway(string ID, string desc):  gateID(ID), desc(desc)
{

	return;
}

void Gateway::setRNG(MyRNG* ref)
{
	theRng = ref;
}

void Gateway::operator << (const YAML::Node& node)
{
	//Assuming gateway has all the right nodes.
	try
	{
		node["ID"] >> this->gateID;
		if(node.FindValue("Desc"))
		{
			node["Desc"] >> this->desc;
		}
		else
		{
			this->desc = "None provided";
		}
		//Address is for the gateway, or for us to assign ourselves.
		//string tmpAddr;
		//node["Adddress"] >> tmpAddr;
		//Even if a CIDR is provided, need to have MaskBits field

		node["MaskBits"] >> this->maskBits;	//Unsigned integer, don't expect negatives

		if(maskBits > 32)
		{
			throw new exception("MaskBits field invalid");
		}

		this->nodeCount = (unsigned int)pow(2, 32 - maskBits);

		const YAML::Node& ntNode = node["NodeTypes"];
		for (YAML::Iterator it = ntNode.begin(); it != ntNode.end() ; it++)
		{
			string tmpNTName;
			(*it) >> tmpNTName;
			
			//must resolve this link later
			this->nodeTypesToAdd.push_back(tmpNTName);
		}

		const YAML::Node& distNode = node["DistType"];
		//Check what the first entry is, if it's random, then mark random flag.
		string distConf;

		//For distribution to be random, first entry MUST be random.
		distNode >> distConf;
		if( distConf == "Random" || distConf == "random" )
		{
			//generate in resolution step
			this->subGraphDist = GraphDist::Random;
			
			//Since we have to link this stuff up in the NetMap, we'll call this later.
			/*if(!generateSubGraph())
			{
				throw exception("Failed to generate random subgraph!");
			}*/

		}
		else if( distConf == "Count" || distConf == "count" )
		{
			this->subGraphDist = GraphDist::Count;
			const YAML::Node& countNode = node["NodeDist"];
			//define and read in our count matrix.
			//Generate a map and pass it to the function so it deletes itself.
			//OLD: map<string, int> tmpCountMap;
			//The gateway should maintain the count map as a member


			for (YAML::Iterator it = distNode.begin(); it != distNode.end(); it++)
			{
				//Key | Value pairs
				string nodeName;
				int nodeCount;
				it.first() >> nodeName;
				it.second() >> nodeCount;

				countMap[nodeName] = nodeCount;
			}
			//Since we have to link this stuff up in the NetMap, we'll call this later.
			/*if(!generateSubGraph(tmpCountMap))
			{
				throw exception("Failed to parse NodeDist counts!");
			}*/
			
		}
		//This case would have to be defined elsewhere as it's another level of abstraction
		/*else if( distConf == "Manual" || distConf == "manual" )
		{
			this->subGraphDist = GraphDist::Manual;

			for (YAML::Iterator it = distNode.begin(); it != distNode.end(); it++)
			{
				
			}
		}*/
		else
		{
			throw new exception("Couldn't determine graph type!");
		}
	}
	catch (exception& ex)
	{
		cout << "[-] Error parsing Gateway node:" << endl << ex.what() << endl;
	}
	return;
}

uint Gateway::getNodeCount()
{
	return this->nodeCount;
}

bool Gateway::generateSubGraph(IPAddress& ipBlock, vector<NodeInstance*>* target)
{
	//This is a random subgraph, generate a subgraph with a chance of each node being created to have a different type, depending on the max node count.
	//Take advantage of the already calculated node count
	//Generate a GatewayMap, representing edge nodes in our super graph
	//We assume linking has already been done. Let's check anyway
	if(! nodeTypes.size())
	{
		cout << "[-] Error generating gateway subgraph template: There are no nodetypes defined" << endl;
		return false;
	}

	if( !theRng )
	{
		cout << "[-] Error generating gateway subraph template: No random number generator was set!" << endl;
		return false;
	}

	//If we have a countmap generated from the COUNT DistType, act as a wrapper for the overloadded countmap method
	if(countMap.size() > 0)
	{
		return generateSubGraph(this->countMap, ipBlock, target);
	}

	MyRNG& rng = (*theRng);
	//Use fancy new C++11 random module
	//Lets assume it was seeded already.
	//Have to create a distribution
	std::uniform_int_distribution<uint32_t> nodeDist(0, nodeTypes.size());
	uint curAddr = ipBlock.getStartAddr()->getIntRep();
	uint endAddr = ipBlock.getEndAddr()->getIntRep();

	for(uint i = 0; i < nodeCount ; i++)
	{
		uint typeIndex = nodeDist(rng);
		if(typeIndex == nodeTypes.size())
		{
			//This address won't be allocated
			continue;
		}
		NodeInstance* tmp = new NodeInstance;
		//tmp-> nAddr //This has to be set by somemone else
		tmp->nStatus = NodeStatus::Clean;
		tmp->nType = nodeTypes[typeIndex];
		tmp->nAddr = curAddr;
		curAddr++;
		if(curAddr > endAddr)
		{
			cout << "[-] Error generating subgraph, allocated too many addresses" << endl;
			return false;
		}

		//Target should be pointing at a live Gateway subgraph
		target->push_back(tmp);
	}

	return true;
}

//Node Map is a count map
//Need to figure out who's responsible for generating the count node map
//Why isn't it the Gateway parser?
bool Gateway::generateSubGraph(map<string, int>& nodeMap, IPAddress& ipBlock, vector<NodeInstance*>* target)
{
	//NodeMap is a mapping given whenever user defines a 'Count' node distribution
	map<string,int>::iterator mit;
	uint nMapCount = 0;

	if(ipBlock.getType() == IPType::Single && nodeMap.size() != 1)
	{
		cout << "[-] Error generating subgraph, not enough addresses provided!" << endl;
		return false;
	}
	for(mit = nodeMap.begin(); mit != nodeMap.end(); mit++)
	{
		nMapCount += mit->second;
	}


	if(ipBlock.getNetworkSize() < nMapCount)
	{
		cout << "[-] Error generating subgraph, not enough addresses provided!" << endl;
		return false;
	}

	uint curAddr = ipBlock.getStartAddr()->getIntRep();
	uint endAddr = ipBlock.getEndAddr()->getIntRep();

	try
	{
		for(mit = nodeMap.begin(); mit != nodeMap.end(); mit++)
		{
			int toCreate = abs(mit->second); //just in case a negative is given.
		
			//Find the required node first.
			uint j = 0;

			for(j = 0; j < nodeTypes.size(); j++)
			{
				if(nodeTypes[0]->getID() == mit->first)
				{
					break;
				}
			}

			for(int i = 0; i < toCreate; i++)
			{
				NodeInstance* tmp = new NodeInstance;
				tmp->nStatus = NodeStatus::Clean;
				tmp->nType = nodeTypes[j];
				tmp->nAddr = curAddr;
				curAddr++;
				if(curAddr > endAddr)
				{
					cout << "[-] Error generating subgraph, allocated too many addresses" << endl;
					return false;
				}
			}
		}
	}
	catch(exception& ex)
	{
		cout << "[-] Error generating gateway subgraph: " << ex.what() << endl;
		return false;
	}

	return true;
	
}