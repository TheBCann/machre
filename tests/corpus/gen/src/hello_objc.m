/* hello-objc: two classes, properties, a protocol, a category -> __objc_* sections. */
#import <Foundation/Foundation.h>

@protocol MachreGreeter <NSObject>
- (NSString *)greet:(NSString *)name;
@optional
- (void)wave;
@end

@interface MachreAnimal : NSObject <MachreGreeter>
@property (nonatomic, copy) NSString *name;
@property (nonatomic, assign) NSInteger legs;
- (instancetype)initWithName:(NSString *)name legs:(NSInteger)legs;
- (NSString *)describe;
+ (NSInteger)population;
@end

@interface MachreDog : MachreAnimal
@property (nonatomic, strong) NSArray<NSString *> *tricks;
- (void)bark;
@end

@interface MachreAnimal (Sounds)   /* same-image category: ld64 merges it into the class (no __objc_catlist entry) */
- (NSString *)sound;
@end

@interface NSString (MachreExtras)  /* category on a class from another image: stays a real category in __objc_catlist */
- (NSString *)machreShout;
@end

static NSInteger gPopulation = 0;

@implementation MachreAnimal
- (instancetype)initWithName:(NSString *)name legs:(NSInteger)legs {
    if ((self = [super init])) { _name = [name copy]; _legs = legs; gPopulation++; }
    return self;
}
- (NSString *)describe { return [NSString stringWithFormat:@"%@ has %ld legs", self.name, (long)self.legs]; }
+ (NSInteger)population { return gPopulation; }
- (NSString *)greet:(NSString *)who { return [NSString stringWithFormat:@"%@ greets %@", self.name, who]; }
@end

@implementation MachreDog
- (void)bark { NSLog(@"%@: woof (%lu tricks)", self.name, (unsigned long)self.tricks.count); }
- (void)wave { NSLog(@"%@ wags", self.name); }
@end

@implementation MachreAnimal (Sounds)
- (NSString *)sound { return @"generic"; }
@end

@implementation NSString (MachreExtras)
- (NSString *)machreShout { return [self uppercaseString]; }
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        MachreDog *d = [[MachreDog alloc] initWithName:@"Rex" legs:4];
        d.tricks = @[@"sit", @"roll"];
        [d bark];
        NSLog(@"%@ / %@ / %@ / %@ / pop=%ld", [d describe], [d greet:@"you"], [d sound], [@"shout" machreShout], (long)[MachreAnimal population]);
    }
    return 0;
}
