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

Gateway::Gateway(string ID, string addr, string desc):  gateID(ID), ipAddr(addr), desc(desc)
{

	return;
}

void Gateway::operator << (const YAML::Node& node)
{
	//Assuming gateway has all the right nodes.
	try
	{
		node["ID"] >> this->gateID;
		node["Desc"] >> this->desc;
		node["Address"] >> this->ipAddr;

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
		}
		else if( distConf == "Count" || distConf == "count" )
		{
			this->subGraphDist = GraphDist::Count;
			const YAML::Node& countNode = node["NodeDist"];
			//define and read in our count matrix.
			//Generate a map and pass it to the function so it deletes itself.
			map<string, int> tmpCountMap;

			for (YAML::Iterator it = distNode.begin(); it != distNode.end(); it++)
			{
				//Key | Value pairs
				string nodeName;
				int nodeCount;
				it.first() >> nodeName;
				it.second() >> nodeCount;

				tmpCountMap[nodeName] = nodeCount;
			}
			if(!generateSubGraph(tmpCountMap))
			{
				throw exception("Failed to parse NodeDist counts!");
			}
		}
		else if( distConf == "Manual" || distConf == "manual" )
		{
			this->subGraphDist = GraphDist::Manual;

			for (YAML::Iterator it = distNode.begin(); it != distNode.end(); it++)
			{
				
			}
		}
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