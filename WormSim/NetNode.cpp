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
