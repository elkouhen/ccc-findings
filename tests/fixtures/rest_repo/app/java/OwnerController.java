package com.example.app;

import org.springframework.web.bind.annotation.*;

@RequestMapping("/owners")
@RestController
public class OwnerController {

    @PostMapping
    public Owner createOwner(@RequestBody Owner owner) {
        return null;
    }

    @GetMapping("/{ownerId}")
    public Owner findOwner(@PathVariable int ownerId) {
        return null;
    }

    @GetMapping
    public java.util.List<Owner> findAll() {
        return null;
    }

    @RequestMapping(method = RequestMethod.PUT, value = "/{ownerId}")
    public void updateOwner(@PathVariable int ownerId, @RequestBody Owner owner) {
    }
}
