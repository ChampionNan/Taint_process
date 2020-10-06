//
//  main.cpp
//  filter_log
//
//  Created by ChampionNan on 2020/9/21.
//  Copyright © 2020 陈炳楠. All rights reserved.
//

#include <algorithm>
#include <iostream>
#include <string>
#include <queue>
#include <map>
#include <fstream>
#include <cstring>
#include <cstdio>

#define M 999997

using namespace std;

string listeners[8] = {"OnNewSubStringCopy", "OnNewSlicedString", "OnNewConcatStringCopy", "NewConsString", "OnNewFromJsonString", "OnNewReplaceRegexpWithString", "OnJoinManyStrings", "ConvertCase"};
string sink_header = "Sink_function:";
string sink_function[22] = {"document.write", "document.writeln", "window.document.write", "window.document.writeln", "document.setCookie", "element.setAttributeon", "element.setAttributecaseAdjustedLocalName", "element.attributeChanged", "element.setInnerHTML", "element.setOuterHTML", "element.insertAdjacentHTML", "setTimeout", "setTimeoutno", "setInterval", "setIntervalno", "Location.setLocation", "HTMLAnchorElement.parseAttribute", "HTMLEmbedElement.parseAttribute", "HTMLIFrameElement.parseAttribute", "HTMLImageElement.parseAttribute", "HTMLScriptElement.parseAttribute", "HTMLScriptElement.setText"};

string sink[23];
char str_sign[M];
vector<vector<string>> data;// only string data

int Taint_info[7] = {4, 5, 7, 8, 9, 11, 12};

unsigned int BKDRHash(string c) {
    char *str = new char[c.length()+1];
    strcpy(str, c.c_str());
    unsigned int seed = 131;
    unsigned int hash = 0;
    while (*str) {
        hash = hash*seed + (*str++);
    }
    return (hash % M);
}

int InListeners(string s) {
    for (int i = 0; i < 8; i ++) {
        if (s == listeners[i]) {
            return 1;
        }
    }
    return 0;
}

int InTaintInfo(int a) {
    return (a == 4 || a == 5 || a == 7 || a == 8 || a == 9 || a == 11 || a == 12);
}

//vector<vector<int>> data;// only string data
int JudgeFlow(vector<string> lines) {
    string from = lines[4];
    string to = lines[2];
    vector<string> from_part;
    vector<string> to_part;
    // from part seperate
    char *strs = new char[from.length()+1];
    strcpy(strs, from.c_str());
    char *d = new char[2];
    strcpy(d, "|");
    char *p = strtok(strs, d);
    while (p) {
        string s = p;
        from_part.push_back(s);
        p = strtok(NULL, d);
    }
    // to part seperate
    char *strs2 = new char[to.length()+1];
    strcpy(strs2, to.c_str());
    char *d2 = new char[2];
    strcpy(d2, "|");
    char *p2 = strtok(strs2, d2);
    while (p2) {
        string s = p2;
        to_part.push_back(s);
        p2 = strtok(NULL, d2);
    }
    // flows already exists but still needs to match the Taint_info and filter the required flows,
    // only existed flows will be scaned all to find the matching
    char hash_value = str_sign[BKDRHash(from_part[1])];
    if (hash_value == '1') {
        int find = 0;
        for (int i = 0; i < data.size(); i++) {
            string back_str = data[i].back();
            string taint_info = data[i][data[i].size()-2];
            // find the flow, now append the next part and change the hash table
            if (str_sign[BKDRHash(back_str)] == hash_value && taint_info == from_part[0] && InTaintInfo(stoi(from_part[0]))) {
                str_sign[BKDRHash(back_str)] = '0';
                data[i].push_back(to_part[0]);
                data[i].push_back(to_part[1]);
                str_sign[BKDRHash(to_part[1])] = '1';
                find = 1;
                return 1;
            }
        }
        // hash == 1 && find == 0 => ERROR!
        if (find == 0) {
            cout << "Find Error! " << endl;
            return 0;
        }
    }
    // find a new flow and fits our requirements
    else {
        if (InTaintInfo(stoi(from_part[0]))) {
            vector<string> header;
            header.push_back(from_part[0]);
            header.push_back(from_part[1]);
            header.push_back(to_part[0]);
            header.push_back(to_part[1]);
            str_sign[BKDRHash(to_part[1])] = '1';
            data.push_back(header);
            return 1;
        }
    }
    return 0;
}

map<int, string> ReadFile(char *address) {
    ifstream infile;
    infile.open(address, ios::in);
    int line_number = -1;
    
    map<int, string> data_sink;
    int array_flag = 0;
    vector<string> array_prior_msg;
    
    while (infile.is_open() && !infile.ios_base::eof()) {
        line_number ++;
        string buffer;
        while (getline(infile, buffer) && buffer.empty()) {
            line_number ++;
            continue;
        }
        string::size_type position = buffer.find("|c");
        if (position != buffer.npos) {
            buffer = buffer.replace(buffer.find("|c"), 1, "|");
        }
        
        vector<string> lines;
        char *strs = new char[buffer.length()+1];
        strcpy(strs, buffer.c_str());
        char *d = new char[2];
        strcpy(d, " ");
        
        char *p = strtok(strs, d);
        while (p) {
            string s = p;
            lines.push_back(s);
            p = strtok(NULL, d);
        }
        if (!InListeners(lines[0])) {
            continue;
        }
        position = lines[2].find('\"');
        if (position != lines[2].npos) {
            lines[2] = lines[2].replace(lines[2].find('\"'), 1, "");
        }
        position = lines[2].rfind('\"');
        if (position != lines[2].npos) {
            lines[2] = lines[2].replace(lines[2].rfind('\"'), 1, "");
        }
        position = lines[4].find('\"');
        if (position != lines[4].npos) {
            lines[2] = lines[4].replace(lines[4].find('\"'), 1, "");
        }
        position = lines[4].find('\"');
        if (position != lines[4].npos) {
            lines[4] = lines[4].replace(lines[2].rfind('\"'), 1, "");
        }
        
        cout << "Before Judgeflow" << buffer << endl;
        
        if (InListeners(lines[0]) && lines[0] != string("OnJoinManyStrings") && array_flag == 0) {
            JudgeFlow(lines);
        }
        else if (InListeners(lines[0])) {
            // eval
            string sink_form = "";
            if (lines[0] == "Sink") {
                string sink_from;
                for (int i = 6; i < lines.size(); i ++) {
                    if (i != lines.size()-1) {
                        sink_from += lines[i];
                        sink_from += " ";
                    }
                }
                sink_from.pop_back();
                string add("Sink_function:eval ");
                data_sink.insert(make_pair(line_number, add+sink_from));
            }
            else {
                string sink_from;
                for (int i = 2; i < lines.size(); i ++) {
                    if (i != lines.size()-1) {
                        sink_from += lines[i];
                        sink_from += " ";
                    }
                }
                string s("|");
                int position = (int)sink_from.find(s, 0);
                sink_form = sink_from.substr(position+1);
                data_sink.insert(make_pair(line_number, lines[0]+" "+sink_form));
                
            }
        }
        else if (lines[0] == "OnJoinManyStrings") {
            array_flag = 1;
            array_prior_msg.clear();
            array_prior_msg.push_back(lines[0]);
            array_prior_msg.push_back(lines[1]);
            array_prior_msg.push_back(lines[2]);
            array_prior_msg.push_back(lines[3]);
            array_prior_msg.push_back(lines[4]);
        }
        else if (array_flag != 0 && array_flag != 9) {
            array_flag = array_flag + 1;
        }
        else if (array_flag == 9) {
            if (lines[1] == "}") {
                array_flag = 0;
            }
            else {
                string from_msg = lines[lines.size()-1];
                from_msg.pop_back();
                string s("|");
                int position = (int)array_prior_msg[4].find(s, 0);
                // pop out from msg(wrong)
                string from_tag = array_prior_msg[4].substr(0, position);
                array_prior_msg.pop_back();
                string from_final = from_tag + "|" + from_msg;
                array_prior_msg.push_back(from_final);
                vector<string> temp(array_prior_msg);
                JudgeFlow(temp);
                array_prior_msg.clear();
                // data.push_back(temp);
            }
        }
    }
    return data_sink;
}

vector<vector<string>> Sink_flow(map<int, string> data_sink) {
    vector<vector<string>> flows;
    
    map<int, string>::iterator iter;
    for (iter = data_sink.begin(); iter != data_sink.end(); iter++) {
        int line_number = iter->first;
        string sink_data = iter->second;
        int correct_flag = 0;
        // already have some flows to connect the sink functions
        if (str_sign[BKDRHash(sink_data)] == 1) {
            correct_flag = 1;
            // traverse all the flows to find the connected one
            for (int i = 0; i < data.size(); i ++) {
                vector<string> one = data[i];
                // find it
                if (str_sign[BKDRHash(one[one.size()-1])] == 1) {
                    // push line number + sink function part
                    vector<string> oneflow(data[i]);
                    oneflow.push_back(to_string(line_number));
                    oneflow.push_back(iter->second);
                    flows.push_back(oneflow);
                    correct_flag = 0;
                    break;
                }
            }
            // Error
            if (correct_flag == 1) {
                cout << "Sink function matching error!" << endl;
            }
        }
    }
    return flows;
}

void save2file(vector<vector<string>> flows, char *address) {
    ofstream outfile;
    int i;
    outfile.open(address, ios::out);
    if (outfile.is_open()) {
        for (i = 0; i < flows.size(); i ++) {
            outfile << "# " << i << '\n';
            for (int j = 0; j < flows[i].size(); j ++) {
                outfile << flows[i][j] << ' ' ;
            }
        }
    }
    else {
        outfile.close();
        cout << address << " file error!" << endl;
        return;
    }
    cout << "Count: " << i << endl;
    outfile.close();
}


int main(int argc, const char * argv[]) {
    // Initial sink
    memset(str_sign, '0', M);
    for (int i = 0; i < 22; i ++) {
        sink[i] = sink_header + sink_function[i];
    }
    sink[22] = "Sink";
    
    map<int, string> data_sink;
    char address[70] = "/Users/apple/Desktop/taint_gitee/process/log_file_15863";
    data_sink = ReadFile(address);
    vector<vector<string>> flows = Sink_flow(data_sink);
    char saveaddr[70] = "/Users/apple/Desktop/taint_gitee/process/log_filiter_result.txt";
    if (remove(saveaddr) == 0) {
        cout << "Delete Success!" << endl;
    }
    else {
        cout << "File not exists! " << endl;
    }
    save2file(flows, saveaddr);
    return 0;
}
