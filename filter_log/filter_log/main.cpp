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
#include <time.h>

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
    unsigned long int hash = 0;
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

int InSink(string s) {
    // cout << "What is sink ?" << s << '\n';
    for (int i = 0; i < 23; i ++) {
        //cout << "sink[i]" << sink[i] << endl;
        if (s == sink[i])
            return 1;
    }
    return 0;
}

int InTaintInfo(int a) {
    return (a == 4 || a == 5 || a == 7 || a == 8 || a == 9 || a == 11 || a == 12);
}

int AllisNum(string s) {
    for (int i = 0; i < s.size(); i++) {
        int temp = (int)s[i];
        if (temp >= 48 && temp <= 57) {
            continue;
        }
        else {
            return 0;
        }
    }
    return 1;
}

//vector<vector<int>> data;// only string data
int JudgeFlow(vector<string> &lines) {
    string from = lines[4];
    string to = lines[2];
    // cout << "!!!!!!!!from: " << from << " to: " << to << '\n';
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
        string s2 = p2;
        to_part.push_back(s2);
        p2 = strtok(NULL, d2);
    }
    int i = 0;
    // cout << "form part ";
    while (i < from_part.size()) {
        // cout << from_part[i] << ' ';
        i++;
    }
    i = 0;
    // cout << "\n to part ";
    while (i < to_part.size()) {
        // cout << to_part[i] << ' ';
        i++;
    }
    // flows already exists but still needs to match the Taint_info and filter the required flows,
    // only existed flows will be scaned all to find the matching
    char hash_value = str_sign[BKDRHash(from_part[1])];
    // cout << "Hash value: " << hash_value << "\nHash position: " << BKDRHash(from_part[1]) << '\n';
    if (hash_value == '1') {
        int find = 0;
        for (int i = 0; i < data.size(); i++) {
            string back_str = data[i].back();
            string taint_info = data[i][data[i].size()-2];
            // cout << "taint string: " << back_str << " taint_info: " << taint_info << '\n';
            // find the flow, now append the next part and change the hash table
            if (str_sign[BKDRHash(back_str)] == hash_value && taint_info == from_part[0] && InTaintInfo(stoi(from_part[0]))) {
                // cout << "Concat!" << '\n';
                str_sign[BKDRHash(back_str)] = '0';
                data[i].push_back(lines[0]);
                data[i].push_back(string("to"));
                data[i].push_back(to_part[0]);
                data[i].push_back(to_part[1]);
                str_sign[BKDRHash(to_part[1])] = '1';
                // cout << "\nDefine to Hash to 1: " << BKDRHash(to_part[1]) << '\n';
                find = 1;
                return 1;
            }
        }
        // hash == 1 && find == 0 => ERROR!
        if (find == 0) {
            // cout << "Find Error! " << endl;
            return 0;
        }
    }
    // find a new flow and fits our requirements
    else {
        int num_flag = AllisNum(from_part[0]);
        int taint_info_num;
        if (num_flag) {
            taint_info_num = stoi(from_part[0]);
        }
        else{
            taint_info_num = -1;
        }
        if (InTaintInfo(taint_info_num)) {
            vector<string> header;
            header.push_back(lines[0]);
            header.push_back(string("from"));
            header.push_back(from_part[0]);
            header.push_back(from_part[1]);
            header.push_back(string("to"));
            header.push_back(to_part[0]);
            header.push_back(to_part[1]);
            str_sign[BKDRHash(to_part[1])] = '1';
            // cout << "\nto_part hash 1: " << BKDRHash(to_part[1]) << '\n';
            data.push_back(header);
            return 1;
        }
    }
    return 0;
}

string& ClearHeadTailSpace(string &str) {
    if (str.empty()) {
        return str;
    }
    str.erase(0,str.find_first_not_of(" "));
    str.erase(str.find_last_not_of(" ") + 1);
    return str;
}

map<string, string> ReadFile(char *address) {
    ifstream infile;
    infile.open(address, ios::in);
    int line_number = -1;
    
    map<string, string> data_sink;
    int array_flag = 0;
    // Join array taint info flag
    vector<string> array_prior_msg;
    string from_tag;
    
    while (infile.is_open() && !infile.ios_base::eof()) {
        line_number ++;
        string buffer;
        // empty line
        while (getline(infile, buffer) && buffer.empty()) {
            line_number ++;
            continue;
        }
        
        string::size_type position = buffer.find("|c");
        //cout << " Before replace |c " << buffer << '\n';
        while (position != buffer.npos) {
            buffer = buffer.replace(buffer.find("|c"), 2, "|");
            position = buffer.find("|c");
        }
        //cout << " After replace |c " << buffer << '\n';
        buffer = ClearHeadTailSpace(buffer);
        vector<string> line;
        char *strs = new char[buffer.length()+1];
        strcpy(strs, buffer.c_str());
        char *d = new char[2];
        strcpy(d, " ");
        
        char *p = strtok(strs, d);
        while (p) {
            string s = p;
            line.push_back(s);
            p = strtok(NULL, d);
        }
        // cout << "Print each line\n" << buffer << '\n';
        if(line.size() < 1) {
            break;
        }
        // cout << InListeners(lines[0]) << ' ' << InSink(lines[0]);
        
        try {
            if (!InListeners(line[0]) && !InSink(line[0]) && array_flag == 0) {
                continue;
            }
        } catch (const char* msg) { // end of file or empty file
            cerr << msg << endl;
            continue;
        }
        
        vector<string> lines;
        // cout << "Line[0] " << line[0] << '\n';
        if (InListeners(line[0]) || InSink(line[0])) {
            lines.push_back(line[0]);
            lines.push_back(line[1]);
            string from("from");
            string to("to");
            long from_index = 0;
            long to_index = 0;
            // vector<string>::iterator iter2 =
            vector<string>::iterator iter = std::find(line.begin(), line.end(), from);
            if (iter == line.end()) {
                cout << "Find from Error! \n" << endl;
                continue;
            }
            else {
                from_index = std::distance(line.begin(), iter);
                iter = std::find(line.begin(), line.end(), to);
                if (iter == line.end() && !InSink(line[0])) {
                    cout << "Find end Error! \n" << endl;
                    continue;
                }
                else if (!InSink(line[0])){
                    to_index = std::distance(line.begin(), iter);
                }
                else {
                    lines.push_back(line[2]);
                    to_index = 0;
                }
            }
            // find the correct string function line
            if (from_index && to_index) {
                string target_info("");
                string source_info("");
                for (long i = to_index+1; i < from_index; i ++) {
                    target_info += line[i];
                    if (i != from_index - 1) {
                        target_info += string(" ");
                    }
                }
                for (long i = from_index+1; i < line.size(); i ++) {
                    source_info += line[i];
                    if (i != line.size() - 1) {
                        source_info += string(" ");
                    }
                }
                lines.push_back(target_info);
                lines.push_back(string("from"));
                lines.push_back(source_info);
            }
            // Sink_function
            else if (from_index != 0 && to_index == 0){
                string source_info("");
                for (long i = from_index+1; i < line.size(); i ++) {
                    source_info += line[i];
                    if (i != line.size() - 1) {
                        source_info += string(" ");
                    }
                }
                lines.push_back(source_info);
            }
        }
        // Choose the last part of join msg part
        else if (!InListeners(line[0]) && !InSink(line[0]) && array_flag != 0){
            lines.push_back(line[line.size()-1]);
        }
        // useless msg
        else{
            continue;
        }
        // cout << "Lines \n" << lines[0] << " \n";
        
        try {
            if (lines.size() > 2) {
                position = lines[2].find('\"');
                // cout << "Processing line[2] " << lines[2] << '\n';
                if (position != lines[2].npos) {
                    lines[2] = lines[2].replace(lines[2].find('\"'), 1, "");
                }
                position = lines[2].rfind('\"', lines[2].length()-1);
                if (position != lines[2].npos) {
                    lines[2] = lines[2].replace(lines[2].rfind('\"', lines[2].length()-1), 1, "");
                }
            }
            // cout << "After Processing line[2] " << lines[2] << '\n';
            //cout << "Line[4]" << lines[4] << '\n';
            if (InListeners(lines[0])) {
                position = lines[4].find('\"');
                // cout << "Processing line[4] " << lines[4] << '\n';
                if (position != lines[4].npos) {
                    lines[4] = lines[4].replace(lines[4].find('\"'), 1, "");
                }
                position = lines[4].rfind('\"', lines[4].length()-1);
                if (position != lines[4].npos) {
                    lines[4] = lines[4].replace(lines[4].rfind('\"', lines[4].length()-1), 1, "");
                }
            }
        } catch (const char* msg) {
            cerr << msg << endl;
            continue;
        }
        //cout << "After Lines[2] \n" << lines[2] << '\n';
        //cout << "Line[0]: " << lines[0] << '\n';
        
        // Processing
        if (InListeners(lines[0]) && lines[0] != string("OnJoinManyStrings") && array_flag == 0) {
            JudgeFlow(lines);
        }
        else if (InSink(lines[0])) {
            // eval
            cout << "Get Sink function" << '\n';
            data_sink.insert(make_pair(lines[0], lines[2]));
            cout << "Sink function data: " << (lines[0]+string(" ")+lines[2]) << '\n';
            string sink_from = "";
            if (lines[0] == "Sink") {
                for (int i = 6; i < lines.size(); i ++) {
                    if (i != lines.size()-1) {
                        sink_from += lines[i];
                        sink_from += " ";
                    }
                }
                sink_from.pop_back();
                string add("Sink_function:eval ");
                //cout << "Sink function data: " << (add+sink_from) << '\n';
                //data_sink.insert(make_pair(line_number, add+sink_from));
            }
            else {
                for (int i = 2; i < lines.size(); i ++) {
                    if (i != lines.size()-1) {
                        sink_from += lines[i];
                        sink_from += " ";
                    }
                }
                string s("|");
                int position = (int)sink_from.find(s, 0);
                sink_from = sink_from.substr(position+1);
                //cout << "Sink function data: " << (lines[0]+sink_from) << '\n';
                //data_sink.insert(make_pair(line_number, lines[0]+" "+sink_from));
                
            }
        }
        else if (lines[0] == string("OnJoinManyStrings")) {
            array_flag = 1;
            array_prior_msg.clear();
            array_prior_msg.push_back(lines[0]);
            array_prior_msg.push_back(lines[1]);
            array_prior_msg.push_back(lines[2]);
            array_prior_msg.push_back(lines[3]);
            array_prior_msg.push_back(lines[4]);
            string s("|");
            int position = (int)array_prior_msg[4].find(s, 0);
            from_tag = array_prior_msg[4].substr(0, position);
            array_prior_msg.pop_back();
        }
        else if (array_flag != 0 && array_flag != 9) {
            array_flag = array_flag + 1;
        }
        else if (array_flag == 9) {
            // Each join msg finished
            if (lines[0] == "}") {
                array_flag = 0;
                array_prior_msg.clear();
            }
            else {
                string from_msg = lines[lines.size()-1];
                from_msg.pop_back();
                // Error empty msg
                if (from_msg.empty()) {
                    continue;
                }
                string from_final = from_tag + "|" + from_msg;
                vector<string> temp;
                for (int i = 0; i < array_prior_msg.size(); i ++) {
                    temp.push_back(array_prior_msg[i]);
                }
                temp.push_back(from_final);
                for (int i = 0; i < temp.size(); i ++) {
                    cout << " " << temp[i] << ' ';
                }
                JudgeFlow(temp);
                // array_prior_msg.clear();
                // data.push_back(temp);
            }
        }
    }
    return data_sink;
}

vector<vector<string>> Sink_flow(map<string, string> data_sink) {
    vector<vector<string>> flows;
    map<string, string>::iterator iter;
    for (iter = data_sink.begin(); iter != data_sink.end(); iter++) {
        string sink_function = iter->first;
        string sink_data = iter->second;
        int pos = (int)sink_data.find("|");
        string concat = sink_data.substr(pos+1);
        // cout << "Sink link part: " << concat << '\n';
        int correct_flag = 0;
        // already have some flows to connect the sink functions
        // cout << "\nSink function Hash: " << BKDRHash(concat) << '\n';
        if (str_sign[BKDRHash(concat)] == '1') {
            // cout << "IN!" << '\n';
            correct_flag = 1;
            // traverse all the flows to find the connected one
            for (int i = 0; i < data.size(); i ++) {
                vector<string> one = data[i];
                // find it
                if (str_sign[BKDRHash(one[one.size()-1])] == '1') {
                    // push line number + sink function part
                    vector<string> oneflow(data[i]);
                    oneflow.push_back(sink_function);
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
    clock_t start, end;
    start = clock();
    memset(str_sign, '0', M);
    for (int i = 0; i < 22; i ++) {
        sink[i] = sink_header + sink_function[i];
        // cout << "sink[i]" << sink[i] << '\n';
    }
    sink[22] = "Sink";
    
    map<string, string> data_sink;
    char address[70] = "/Users/apple/Desktop/taint_gitee/process/log_file_15863";
    data_sink = ReadFile(address);
    
    vector<vector<string>> flows = Sink_flow(data_sink);
    char saveaddr[70] = "/Users/apple/Desktop/taint_gitee/process/log_filiter_result_c++.txt";
    if (remove(saveaddr) == 0) {
        cout << "Delete Success!" << endl;
    }
    else {
        cout << "File not exists! " << endl;
    }
    //cout << "flows " << flows[0][0] << '\n';
    save2file(flows, saveaddr);
    end = clock();
    cout << "Runtime: " << (double)(end-start)/CLOCKS_PER_SEC << 's' << '\n';
    return 0;
}
