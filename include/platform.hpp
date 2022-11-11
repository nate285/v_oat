#ifndef PLATFORM_HPP
#define PLATFORM_HPP


class platform {
    private:
    // std::vector<ballot> ballots;
    bool verify();

    public:
    platform();
    platform(const platform &) = delete;
    platform(platform &&) = delete;
    platform &operator=(platform) = delete;

};

#endif