

#include "Math/gfp.h"
#include "Math/gf2n.h"
#include "Networking/sockets.h"
#include "Networking/ssl_sockets.h"
#include "Tools/int.h"
#include "Math/Setup.h"
#include "Protocols/fake-stuff.h"

#include "Math/gfp.hpp"

#include <sodium.h>
#include <iostream>
#include <sstream>
#include <fstream>

// Send the private inputs masked with a random value.
// Receive shares of a preprocessed triple from each SPDZ engine, combine and check the triples are valid.
// Add the private input value to triple[0] and send to each spdz engine.
template<class T>
void send_private_inputs(const vector<T>& values, vector<ssl_socket*>& sockets, int nparties)
{
    int num_inputs = values.size();
    octetStream os;
    vector< vector<T> > triples(num_inputs, vector<T>(3));
    vector<T> triple_shares(3);

    // Receive num_inputs triples from SPDZ
    for (int j = 0; j < nparties; j++)
    {
        os.reset_write_head();
        os.Receive(sockets[j]);

#ifdef VERBOSE_COMM
        cerr << "received " << os.get_length() << " from " << j << endl;
#endif

        for (int j = 0; j < num_inputs; j++)
        {
            for (int k = 0; k < 3; k++)
            {
                triple_shares[k].unpack(os);
                triples[j][k] += triple_shares[k];
            }
        }
    }

    // Check triple relations (is a party cheating?)
    for (int i = 0; i < num_inputs; i++)
    {
        if (T(triples[i][0] * triples[i][1]) != triples[i][2])
        {
            cerr << triples[i][2] << " != " << triples[i][0] << " * " << triples[i][1] << endl;
            cerr << "Incorrect triple at " << i << ", aborting\n";
            throw mac_fail();
        }
    }
    // Send inputs + triple[0], so SPDZ can compute shares of each value
    os.reset_write_head();
    for (int i = 0; i < num_inputs; i++)
    {
        T y = values[i] + triples[i][0];
	cout << values[i];
	cout << triples[i][0];
	cout << "Next";
        y.pack(os);
    }
    for (int j = 0; j < nparties; j++)
        os.Send(sockets[j]);
}

// Receive shares of the result and sum together.
// Also receive authenticating values.
template<class T>
T receive_result(vector<ssl_socket*>& sockets, int nparties)
{
    vector<T> output_values(3);
    octetStream os;
    for (int i = 0; i < nparties; i++)
    {
        os.reset_write_head();
        os.Receive(sockets[i]);
        for (unsigned int j = 0; j < 3; j++)
        {
            T value;
            value.unpack(os);
            output_values[j] += value;
        }
    }

    if (T(output_values[0] * output_values[1]) != output_values[2])
    {
        cerr << "Unable to authenticate output value as correct, aborting." << endl;
        throw mac_fail();
    }
    return output_values[0];
}

template<class T>
void one_run(vector<T>& values, vector<ssl_socket*>& sockets, int nparties)
{
    // Run the computation

    send_private_inputs<T>(values, sockets, nparties);
    cout << "Sent private inputs to each SPDZ engine, waiting for result..." << endl;

    // Get the result back (client_id of winning client)
    T result1 = receive_result<T>(sockets, nparties);
    //T result2 = receive_result<T>(sockets, nparties);
    //T result3 = receive_result<T>(sockets, nparties);

    cout << "Accuracy is : " << result1 << endl;
}

template<class T>
void run(vector<T>& values, vector<ssl_socket*>& sockets, int nparties)
{
    // sint
    //one_run<T>(long(round(salary_value)), sockets, nparties);
    // sfix with f = 16
    //one_run<T>(long(round(salary_value * exp2(16))), sockets, nparties);
    cout << "Run \n";
    for(std::vector<Z2<64> >::size_type i=0; i<values.size(); ++i)
           std::cout << values[i] << ' ';
    one_run<T>(values, sockets, nparties);


}

int main(int argc, char** argv)
{
    int my_client_id;
    int nparties;
    int finish;
    int port_base = 14000;


    my_client_id = atoi(argv[1]);
    nparties = atoi(argv[2]);
    finish = atoi(argv[3]);
    vector<const char*> hostnames(nparties, "localhost");

    vector<Z2<64>> data;

    std::fstream myfile("data.txt", std::ios_base::in);

    double a;
    while (myfile >> a)
    {
        data.push_back(long(round(a)));
    }

    for(std::vector<Z2<64> >::size_type i=0; i<data.size(); ++i)
           std::cout << data[i] << ' ';

    //for (int x : labels_inputs)
    //        data.push_back(x);

    if (argc > 4)
    {
        if (argc < 4 + nparties)
        {
            cerr << "Not enough hostnames specified";
            exit(1);
        }

        for (int i = 0; i < nparties; i++)
            hostnames[i] = argv[4 + i];
    }

    if (argc > 4 + nparties)
        port_base = atoi(argv[4 + nparties]);

    bigint::init_thread();

    // Setup connections from this client to each party socket
    vector<int> plain_sockets(nparties);
    vector<ssl_socket*> sockets(nparties);
    ssl_ctx ctx("C" + to_string(my_client_id));
    ssl_service io_service;
    octetStream specification;
    for (int i = 0; i < nparties; i++)
    {
        set_up_client_socket(plain_sockets[i], hostnames[i], port_base + i);
        send(plain_sockets[i], (octet*) &my_client_id, sizeof(int));
        sockets[i] = new ssl_socket(io_service, ctx, plain_sockets[i],
                "P" + to_string(i), "C" + to_string(my_client_id), true);
        if (i == 0)
            specification.Receive(sockets[0]);
        octetStream os;
        os.store(finish);
        os.Send(sockets[i]);
    }
    cout << "Finish setup socket connections to SPDZ engines." << endl;

    int type = specification.get<int>();
    switch (type)
    {
    case 'p':
    {
        gfp::init_field(specification.get<bigint>());
        cerr << "using prime " << gfp::pr() << endl;
        //run<gfp>(data, sockets, nparties);
        break;
    }
    case 'R':
    {
        int R = specification.get<int>();
        switch (R)
        {
        case 64:
            run<Z2<64>>(data, sockets, nparties);
            break;
        case 104:
            //run<Z2<104>>(data, sockets, nparties);
            break;
        case 128:
            //run<Z2<128>>(data, sockets, nparties);
            break;
        default:
            cerr << R << "-bit ring not implemented";
            exit(1);
        }
        break;
    }
    default:
        cerr << "Type " << type << " not implemented";
        exit(1);
    }

    for (int i = 0; i < nparties; i++)
        delete sockets[i];

    return 0;
}
